let allPlans = [];
let activeNetwork = "All";
let selectedPlan = null;
let paystackPublicKey = "";
let networkConfirmed = true; // becomes false when a mismatch is detected and needs confirming

const plansGrid = document.getElementById("plansGrid");
const networkTabs = document.getElementById("networkTabs");
const drawer = document.getElementById("orderDrawer");
const overlay = document.getElementById("overlay");
const closeDrawer = document.getElementById("closeDrawer");
const payBtn = document.getElementById("payBtn");
const phoneInput = document.getElementById("phoneInput");
const emailInput = document.getElementById("emailInput");

// Common Nigerian prefixes by network. Not exhaustive — number portability
// means some numbers have switched networks, so this is a helpful guess,
// not a guarantee.
const PREFIX_MAP = {
  MTN: ["0803","0806","0703","0706","0813","0814","0816","0810","0906","0916","0704"],
  Glo: ["0805","0807","0705","0815","0811","0905","0915"],
  Airtel: ["0802","0808","0708","0812","0701","0902","0901","0904","0907","0912"],
  "9mobile": ["0809","0817","0818","0908","0909","0917","0918"],
};

function detectNetworkFromPhone(phone) {
  const digits = phone.replace(/\D/g, "");
  if (digits.length < 4) return null;
  const prefix = digits.slice(0, 4);
  const match = Object.entries(PREFIX_MAP).find(([, prefixes]) => prefixes.includes(prefix));
  return match ? match[0] : null;
}

async function init() {
  renderAccountArea();

  const configRes = await fetch("/api/config");
  const config = await configRes.json();
  paystackPublicKey = config.paystackPublicKey;

  const plansRes = await fetch("/api/plans");
  allPlans = await plansRes.json();

  renderNetworkTabs();
  renderPlans();
}

function renderAccountArea() {
  const accountArea = document.getElementById("accountArea");
  if (!accountArea) return;

  const phone = localStorage.getItem("authPhone");
  if (phone) {
    accountArea.innerHTML = `Logged in as ${phone} · <a href="#" id="logoutLink" style="color:inherit;text-decoration:underline;">Log out</a>`;
    document.getElementById("logoutLink").onclick = (e) => {
      e.preventDefault();
      localStorage.removeItem("authToken");
      localStorage.removeItem("authPhone");
      renderAccountArea();
    };
  } else {
    accountArea.innerHTML = `<a href="/login.html" style="color:inherit;text-decoration:underline;">Log in / Sign up</a>`;
  }
}

function renderNetworkTabs() {
  const networks = ["All", ...new Set(allPlans.map((p) => p.network))];
  networkTabs.innerHTML = "";
  networks.forEach((net) => {
    const chip = document.createElement("div");
    chip.className = "network-chip" + (net === activeNetwork ? " active" : "");
    chip.textContent = net;
    chip.onclick = () => {
      activeNetwork = net;
      renderNetworkTabs();
      renderPlans();
    };
    networkTabs.appendChild(chip);
  });
}

function renderPlans() {
  const filtered =
    activeNetwork === "All"
      ? allPlans
      : allPlans.filter((p) => p.network === activeNetwork);

  plansGrid.innerHTML = "";

  if (filtered.length === 0) {
    plansGrid.innerHTML = '<p class="loading">No plans found.</p>';
    return;
  }

  filtered.forEach((plan) => {
    const card = document.createElement("div");
    card.className = "plan-card";
    card.innerHTML = `
      <div class="plan-network">${plan.network}</div>
      <div class="plan-label">${plan.label}</div>
      <div class="plan-price">₦${plan.priceNaira.toLocaleString()}</div>
    `;
    card.onclick = () => openDrawer(plan);
    plansGrid.appendChild(card);
  });
}

function openDrawer(plan) {
  if (!localStorage.getItem("authToken")) {
    window.location.href = "/login.html?redirect=" + encodeURIComponent(window.location.pathname);
    return;
  }
  selectedPlan = plan;
  networkConfirmed = true;
  document.getElementById("drawerPlanLabel").textContent = `${plan.network} — ${plan.label}`;
  document.getElementById("drawerPlanPrice").textContent = `₦${plan.priceNaira.toLocaleString()}`;
  document.getElementById("networkWarning").innerHTML = "";
  drawer.classList.add("show");
  overlay.classList.add("show");
}

phoneInput.addEventListener("input", () => {
  const warningBox = document.getElementById("networkWarning");
  const digits = phoneInput.value.replace(/\D/g, "").slice(0, 11);
  phoneInput.value = digits;

  if (!selectedPlan || digits.length < 4) {
    warningBox.innerHTML = "";
    networkConfirmed = true;
    return;
  }

  const detected = detectNetworkFromPhone(digits);

  if (detected && detected !== selectedPlan.network) {
    networkConfirmed = false;
    warningBox.innerHTML = `
      <div style="border:1px solid #d97706;background:#3a2a0a;border-radius:8px;padding:10px;margin:8px 0;">
        <p style="color:#fbbf24;">⚠️ This number looks like <strong>${detected}</strong>, but you selected a <strong>${selectedPlan.network}</strong> plan. Data sent to the wrong network cannot be refunded.</p>
        <label style="display:flex;align-items:center;gap:8px;margin-top:8px;">
          <input type="checkbox" id="confirmMismatch">
          I've checked and this is correct — proceed anyway
        </label>
      </div>
    `;
    document.getElementById("confirmMismatch").addEventListener("change", (e) => {
      networkConfirmed = e.target.checked;
    });
  } else {
    networkConfirmed = true;
    warningBox.innerHTML = detected
      ? `<p style="opacity:0.7;margin:8px 0;">✅ Detected network: ${detected}, matches your selected plan.</p>`
      : "";
  }
});

function hideDrawer() {
  drawer.classList.remove("show");
  overlay.classList.remove("show");
}

closeDrawer.onclick = hideDrawer;
overlay.onclick = hideDrawer;

payBtn.onclick = async () => {
  const phone = phoneInput.value.trim();
  const email = emailInput.value.trim();

  if (!phone || phone.length < 10) {
    alert("Enter a valid phone number to receive the data.");
    return;
  }
  if (!networkConfirmed) {
    alert("This number looks like a different network than the plan you selected. Please check the box to confirm before paying, or double-check the number.");
    return;
  }
  if (!email || !email.includes("@")) {
    alert("Enter a valid email for your receipt.");
    return;
  }
  if (!paystackPublicKey) {
    alert("Payment isn't configured yet — the store owner needs to add a Paystack public key.");
    return;
  }

  payBtn.disabled = true;
  payBtn.textContent = "Starting payment…";

  try {
    const initRes = await fetch("/api/orders/initialize", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + localStorage.getItem("authToken"),
      },
      body: JSON.stringify({ planId: selectedPlan.id, phone, email }),
    });
    const initData = await initRes.json();

    if (initRes.status === 401) {
      alert("Your session has expired. Please log in again.");
      window.location.href = "/login.html?redirect=" + encodeURIComponent(window.location.pathname);
      return;
    }

    if (!initRes.ok) {
      alert(initData.error || "Could not start payment.");
      payBtn.disabled = false;
      payBtn.textContent = "Pay now";
      return;
    }

    const handler = PaystackPop.setup({
      key: paystackPublicKey,
      email,
      amount: selectedPlan.priceNaira * 100,
      ref: initData.reference,
      callback: function (response) {
        verifyPayment(response.reference);
      },
      onClose: function () {
        payBtn.disabled = false;
        payBtn.textContent = "Pay now";
      },
    });
    handler.openIframe();
  } catch (err) {
    console.error(err);
    alert("Something went wrong. Please try again.");
    payBtn.disabled = false;
    payBtn.textContent = "Pay now";
  }
};

async function verifyPayment(reference) {
  payBtn.textContent = "Confirming payment…";
  try {
    const res = await fetch(`/api/orders/verify/${reference}`);
    const data = await res.json();

    if (data.status === "paid") {
      alert("Payment received! Your data will be delivered shortly.\n\nYour order reference is:\n" + reference + "\n\nSave this — you can use it with your phone number at /check-order.html to check your order status anytime.");
      hideDrawer();
      phoneInput.value = "";
      emailInput.value = "";
    } else {
      alert("Payment could not be confirmed. If you were charged, please contact support.");
    }
  } catch (err) {
    console.error(err);
    alert("Could not confirm payment status. Please contact support with your reference: " + reference);
  } finally {
    payBtn.disabled = false;
    payBtn.textContent = "Pay now";
  }
}

init();
