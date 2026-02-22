// Visibility Logic
document.querySelectorAll('input[name="scannerType"]').forEach((elem) => {
  elem.addEventListener("change", function (event) {
    const sectionClassic = document.getElementById("scope-section-classic");
    const sectionML = document.getElementById("scope-section-ml");

    // Hide both initially
    sectionClassic.classList.add("d-none");
    sectionML.classList.add("d-none");

    if (this.value === "automated") {
      sectionClassic.classList.remove("d-none");
    } else if (this.value === "ml") {
      sectionML.classList.remove("d-none");
    }
  });
});

document.getElementById("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = document.getElementById("website-url").value.trim();

  const scannerTypeInput = document.querySelector(
    'input[name="scannerType"]:checked',
  );
  if (!scannerTypeInput) {
    alert("Please select a Scanner Type (Automated or ML).");
    return;
  }
  const scannerType = scannerTypeInput.value;

  // Get Scan Scope based on type
  let scanScope;
  if (scannerType === "automated") {
    scanScope = document.querySelector(
      'input[name="scanScopeClassic"]:checked',
    ).value;
  } else {
    scanScope = document.querySelector(
      'input[name="scanScopeML"]:checked',
    ).value;
  }
  const runSql = scanScope === "full" || scanScope === "sqli";
  const runXss = scanScope === "full" || scanScope === "xss";

  const resultsContainer = document.getElementById("results-container");

  // Show a loading message with progress bar
  resultsContainer.innerHTML = `
    <div class="text-center">
      <div class="progress mb-4" style="height: 25px;">
        <div id="scan-progress-bar" class="progress-bar progress-bar-striped progress-bar-animated bg-dark" 
             role="progressbar" 
             style="width: 1%;" 
             aria-valuenow="1" 
             aria-valuemin="0" 
             aria-valuemax="100">1%</div>
      </div>
      <div class="d-flex justify-content-center align-items-center">
        <div class="spinner-border" role="status">
          <span class="visually-hidden">Loading...</span>
        </div>
        <p class="ms-3 mb-0">Scanning... This may take a moment.</p>
      </div>
    </div>
  `;

  console.log("Progress bar HTML set, container:", resultsContainer);

  // Animate progress bar - use setTimeout to ensure DOM is updated
  let progress = 1;
  let progressInterval;

  setTimeout(() => {
    const progressBar = document.getElementById("scan-progress-bar");
    console.log("Looking for progress bar element:", progressBar);
    if (progressBar) {
      console.log("Progress bar found! Starting animation...");
      progressInterval = setInterval(() => {
        if (progress < 95) {
          progress += Math.random() * 2 + 1; // Random increment between 1-4%
          if (progress > 95) progress = 95;
          progressBar.style.width = Math.floor(progress) + "%";
          progressBar.setAttribute("aria-valuenow", Math.floor(progress));
          progressBar.textContent = Math.floor(progress) + "%";
        }
      }, 1600);
    } else {
      console.error("ERROR: Progress bar element not found!");
    }
  }, 50);

  try {
    const response = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        scannerType,
        runSql,
        runXss,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || "Scan failed");
    }

    const results = await response.json();

    // Complete progress bar
    if (progressInterval) clearInterval(progressInterval);
    const progressBar = document.getElementById("scan-progress-bar");
    if (progressBar) {
      progressBar.style.width = "100%";
      progressBar.setAttribute("aria-valuenow", 100);
      progressBar.textContent = "100%";
    }

    // Save results to sessionStorage for the report page
    sessionStorage.setItem("scanResults", JSON.stringify(results));
    displayResults(results);
  } catch (error) {
    if (progressInterval) clearInterval(progressInterval);
    resultsContainer.innerHTML = `<div class="alert alert-danger">${error.message}</div>`;
  }
});

function displayResults(data) {
  const resultsContainer = document.getElementById("results-container");

  if (!data || data.error) {
    resultsContainer.innerHTML = `<div class="alert alert-danger">${
      data.error || "An unknown error occurred."
    }</div>`;
    return;
  }

  // Calculate summary stats
  const vulnCount = data.vulnerabilities ? data.vulnerabilities.length : 0;
  const uniqueTypes = data.vulnerabilities
    ? [...new Set(data.vulnerabilities.map((v) => v.type))].join(", ")
    : "None";

  let html = `
    <div class="card text-center shadow">
      <div class="card-header bg-dark text-white">
        Scan Complete
      </div>
      <div class="card-body">
        <h5 class="card-title">Target: ${data.target}</h5>
        <p class="card-text mt-3">
            <span class="display-6 fw-bold ${vulnCount > 0 ? "text-danger" : "text-success"}">
                ${vulnCount}
            </span>
            <br>
            <span class="text-muted">Vulnerabilities Found</span>
        </p>
        ${vulnCount > 0 ? `<p class="text-muted">Types found: ${uniqueTypes}</p>` : ""}
        
        <a href="report.html" class="btn btn-primary mt-3">Show Full Report</a>
      </div>
      <div class="card-footer text-body-secondary">
        ${data.urls_scanned} URLs scanned
      </div>
    </div>
  `;

  resultsContainer.innerHTML = html;
}
