document.addEventListener("DOMContentLoaded", () => {
  const reportContainer = document.getElementById("report-container");
  const storedData = sessionStorage.getItem("scanResults");

  if (!storedData) {
    reportContainer.innerHTML = `
            <div class="alert alert-warning text-center">
                <h4>No report data found.</h4>
                <p>Please perform a scan first.</p>
                <a href="serviceclassic.html" class="btn btn-primary">Go to Scanner</a>
            </div>
        `;
    return;
  }

  try {
    const data = JSON.parse(storedData);
    renderReport(data, reportContainer);

    // PDF Download Listener
    document.getElementById("download-pdf").addEventListener("click", () => {
      generatePDF(data);
    });
  } catch (e) {
    console.error("Error parsing scan results:", e);
    reportContainer.innerHTML = `<div class="alert alert-danger">Error loading report data.</div>`;
  }
});

function renderReport(data, container) {
  if (!data || data.error) {
    container.innerHTML = `<div class="alert alert-danger">${
      data.error || "An unknown error occurred."
    }</div>`;
    return;
  }

  // --- Statistics Calculation ---
  const vulns = data.vulnerabilities || [];
  const totalVulns = vulns.length;

  // Unique Vulnerable URLs
  const uniqueVulnUrls = new Set(vulns.map((v) => v.url));
  const vulnUrlCount = uniqueVulnUrls.size;

  // Group by URL for Sidebar (Count per Page)
  const vulnsByPage = {};
  vulns.forEach((v) => {
    vulnsByPage[v.url] = (vulnsByPage[v.url] || 0) + 1;
  });

  // Smart Duration Formatting
  let durationDisplay = "0s";
  if (data.duration_seconds) {
    if (data.duration_seconds < 60) {
      durationDisplay = data.duration_seconds.toFixed(1) + "s";
    } else {
      const mins = Math.floor(data.duration_seconds / 60);
      const secs = Math.round(data.duration_seconds % 60);
      durationDisplay = `${mins}m ${secs}s`;
    }
  }

  const dateStr = data.scan_start
    ? new Date(data.scan_start).toLocaleString()
    : new Date().toLocaleString();

  // --- HTML Generation ---

  let html = `
    <div class="row">
        <!-- Sidebar (Sticky) -->
        <div class="col-md-3" style="margin-left: -180px">
            <div style="position: sticky; top: 20px; z-index: 100;">
                <div class="mb-4">
                     <input type="text" id="target-filter" class="form-control form-control-sm" placeholder="Filter targets..." style="background-color: #f8f9fa; border-radius: 4px;">
                </div>

                <!-- Navigation -->
                <div class="list-group list-group-flush mb-4">
                     <a href="#" class="list-group-item list-group-item-action border-0 d-flex align-items-center py-2 px-3 mb-1 rounded-1" 
                        style="background-color: #eef4ff; color: #3b82f6; font-weight: 600; border-left: 3px solid #3b82f6 !important;">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bar-chart-fill me-3" viewBox="0 0 16 16">
                            <path d="M1 11a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1v-3zm5-4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V7zm5-5a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V2z"/>
                        </svg>
                        Scan Summary
                     </a>
                </div>

                <!-- Vulnerable Pages List -->
                <div class="mb-3">
                    <p class="text-uppercase text-secondary fw-bold mb-2 ps-2" style="font-size: 0.7rem; letter-spacing: 0.5px;">Vulnerable Pages</p>
                    <ul id="vulnerable-pages-list" class="list-group list-group-flush custom-scrollbar" style="max-height: calc(100vh - 250px); overflow-y: auto;">
    `;

  // Sidebar Items
  for (const [url, count] of Object.entries(vulnsByPage)) {
    // Format path: remove origin
    let displayPath = url;
    try {
      const parsed = new URL(url);
      displayPath = parsed.pathname;
      if (displayPath.length > 20) {
        displayPath = displayPath.substring(0, 20) + "...";
      }
    } catch (e) {}

    // Truncate
    if (displayPath.length > 30)
      displayPath = displayPath.substring(0, 28) + "...";

    html += `
            <li class="list-group-item d-flex justify-content-between align-items-center border-0 px-2 py-1 mb-1 bg-transparent" data-url="${escapeHtml(
              url,
            ).toLowerCase()}">
                <div class="d-flex align-items-center text-truncate" title="${escapeHtml(
                  url,
                )}" style="max-width: 85%;">
                    <i class="bi bi-file-earmark me-2 text-muted" style="font-size: 0.8rem;"></i>
                    <span class="text-secondary small" style="font-family: monospace; font-size: 0.75rem;">${escapeHtml(
                      displayPath,
                    )}</span>
                </div>
                <span class="badge rounded-pill text-secondary bg-light border" style="font-size: 0.7rem; min-width: 20px;">${count}</span>
            </li>
        `;
  }

  html += `
                    </ul>
                </div>
            </div> <!-- End Sticky Wrapper -->
        </div>

        <!-- Main Content -->
        <div class="col-md-12 ps-md-4" style = "margin-right: -200px">
            
            <div class="d-flex align-items-center mb-4">
                 <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" fill="#3b82f6" class="bi bi-bar-chart-fill me-2" viewBox="0 0 16 16">
                    <path d="M1 11a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1v-3zm5-4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V7zm5-5a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1h-2a1 1 0 0 1-1-1V2z"/>
                 </svg>
                 <h5 class="fw-bold text-dark mb-0">Scan Summary</h5>
            </div>

            <!-- Quick Stats Row -->
            <div class="row justify-content-center g-3 mb-5">
                <div class="col-md-3">
                    <div class="card border-0 shadow-sm h-100 py-3">
                        <div class="card-body text-center p-0">
                            <h2 class="fw-bold text-danger mb-1">${totalVulns}</h2>
                            <span class="text-secondary text-uppercase fw-bold" style="font-size: 0.65rem; letter-spacing: 0.5px;">Unique Vulns</span>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card border-0 shadow-sm h-100 py-3">
                        <div class="card-body text-center p-0">
                            <h2 class="fw-bold text-primary mb-1">${
                              data.urls_scanned || 0
                            }</h2>
                            <span class="text-secondary text-uppercase fw-bold d-block mb-2" style="font-size: 0.65rem; letter-spacing: 0.5px;">Pages Scanned</span>
                            
                            <div class="d-flex justify-content-center gap-2">
                                <span class="badge bg-light text-secondary border" style="font-size: 0.65rem; font-weight: 500;">
                                    SQLi: ${data.urls_scanned_details?.sqli || 0}
                                </span>
                                <span class="badge bg-light text-secondary border" style="font-size: 0.65rem; font-weight: 500;">
                                    XSS: ${data.urls_scanned_details?.xss || 0}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card border-0 shadow-sm h-100 py-3">
                        <div class="card-body text-center p-0">
                            <h2 class="fw-bold text-info mb-1">${durationDisplay}</h2>
                            <span class="text-secondary text-uppercase fw-bold" style="font-size: 0.65rem; letter-spacing: 0.5px;">Duration</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Configuration Section -->
            <div class="mb-5">
                <h6 class="fw-bold mb-3">Configuration</h6>
                <div class="card border-0 shadow-sm">
                    <div class="card-body py-3 px-4">
                        <div class="row g-2" style="font-size: 0.85rem;">
                            <div class="col-md-12 mb-2">
                                <div class="d-flex">
                                    <span class="text-secondary fw-semibold" style="width: 100px;">Target:</span>
                                    <a href="${escapeHtml(
                                      data.target,
                                    )}" target="_blank" class="text-primary text-decoration-none">${escapeHtml(
                                      data.target,
                                    )}</a>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="d-flex">
                                    <span class="text-secondary fw-semibold" style="width: 100px;">Start Time:</span>
                                    <span class="text-dark">${escapeHtml(
                                      dateStr,
                                    )}</span>
                                </div>
                            </div>
                            <div class="col-md-6"></div>
                            <div class="col-md-6">
                                <div class="d-flex">
                                    <span class="text-secondary fw-semibold" style="width: 100px;">Total Tests:</span>
                                    <span class="text-dark">${
                                      data.total_tests || 0
                                    }</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Findings Table -->
            <div class="d-flex align-items-center mb-3">
                <h6 class="fw-bold mb-0">
                    <span class="text-warning me-2">⚠️</span> Vulnerability Findings
                </h6>
            </div>

            <div class="card border-0 shadow-sm">
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0" style="font-size: 0.8rem;">
                        <thead class="bg-white text-uppercase" style="border-bottom: 2px solid #f0f0f0;">
                            <tr>
                                <th class="ps-4 py-3 fw-bold text-dark" style="font-size: 0.7rem;">Severity</th>
                                <th class="py-3 fw-bold text-dark" style="font-size: 0.7rem;">Vulnerability</th>
                                <th class="py-3 fw-bold text-dark" style="font-size: 0.7rem;">URL</th>
                                <th class="py-3 fw-bold text-dark" style="font-size: 0.7rem;">Parameter</th>
                                <th class="pe-4 py-3 text-end fw-bold text-dark" style="font-size: 0.7rem;">Confidence %</th>
                            </tr>
                        </thead>
                        <tbody class="border-top-0">
    `;

  if (totalVulns === 0) {
    html += `<tr><td colspan="6" class="text-center py-5 text-muted">No vulnerabilities found.</td></tr>`;
  } else {
    vulns.forEach((vuln) => {
      // Determine Severity (Image style: Light Red background, Red Text)
      let sevBadge = `<span class="badge" style="background-color: #e0f2f1; color: #00695c; font-weight: 600; font-size: 0.7rem; padding: 5px 10px;">LOW</span>`;
      if (vuln.confidence >= 90)
        sevBadge = `<span class="badge" style="background-color: #ffebee; color: #c62828; font-weight: 600; font-size: 0.7rem; padding: 5px 10px;">HIGH</span>`;
      else if (vuln.confidence >= 50)
        sevBadge = `<span class="badge" style="background-color: #fff8e1; color: #ff8f00; font-weight: 600; font-size: 0.7rem; padding: 5px 10px;">MEDIUM</span>`;

      // Parameter Badge (Image style: similar to severity or light gray)
      const paramBadge = `<span class="badge" style="background-color: #ffebee; color: #c62828; font-weight: 500; font-size: 0.7rem; border: 1px solid #ffcdd2;">${escapeHtml(
        vuln.parameter,
      )}</span>`;

      const fullPayload = escapeHtml(vuln.payload);

      html += `
                <tr>
                    <td class="ps-4 py-3">${sevBadge}</td>
                    <td class="text-secondary fw-normal">${escapeHtml(
                      vuln.type,
                    )}</td>
                    <td class="text-truncate" style="max-width: 250px;">
                        <a href="${escapeHtml(
                          vuln.url,
                        )}" target="_blank" class="text-decoration-none" style="color: #2196f3;">${escapeHtml(
                          vuln.url.split("?")[0],
                        )}</a>
                    </td>
                    <td>${paramBadge}</td>

                    <td class="pe-4 text-end text-dark">${vuln.confidence}%</td>
                </tr>
            `;
    });
  }

  html += `
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="mt-5 mb-4 text-center">
                 <p class="text-muted small" style="font-size: 0.7rem;">Generated by VScan - Advanced Security Scanner</p>
            </div>

        </div> <!-- End Col-9 -->
    </div> <!-- End Row -->
    `;

  container.innerHTML = html;

  // --- Post-Render: Attach Filter Listener ---
  const filterInput = document.getElementById("target-filter");
  if (filterInput) {
    filterInput.addEventListener("input", (e) => {
      const term = e.target.value.toLowerCase().trim();
      const listItems = document.querySelectorAll("#vulnerable-pages-list li");

      listItems.forEach((item) => {
        const url = item.getAttribute("data-url") || "";
        if (url.includes(term)) {
          item.style.display = "flex"; // Restore d-flex
        } else {
          item.style.display = "none";
        }
      });
    });
  }
}

function generatePDF(data) {
  const btn = document.getElementById("download-pdf");
  const originalText = btn.innerText;
  btn.innerText = "Generating...";
  btn.disabled = true;

  // Create a simplified, linear clone for PDF generation
  const printContainer = document.createElement("div");
  printContainer.style.padding = "40px";
  printContainer.style.fontFamily = "Arial, sans-serif";
  printContainer.style.background = "#ffffff";
  printContainer.style.color = "#333";

  // --- Header ---
  const dateStr = data.scan_start
    ? new Date(data.scan_start).toLocaleString()
    : new Date().toLocaleString();
  const vulns = data.vulnerabilities || [];

  // Smart Duration
  let durationDisplay = "0s";
  if (data.duration_seconds) {
    if (data.duration_seconds < 60)
      durationDisplay = data.duration_seconds.toFixed(1) + "s";
    else {
      const mins = Math.floor(data.duration_seconds / 60);
      const secs = Math.round(data.duration_seconds % 60);
      durationDisplay = `${mins}m ${secs}s`;
    }
  }

  printContainer.innerHTML = `
        <div style="text-align: center; margin-bottom: 30px; border-bottom: 2px solid #3b82f6; padding-bottom: 20px;">
            <h1 style="color: #1a1a1a; margin-bottom: 10px;">VScan Security Report</h1>
            <p style="color: #666; font-size: 14px; margin: 0;">Target: <strong>${escapeHtml(data.target)}</strong></p>
            <p style="color: #666; font-size: 14px; margin: 0;">Generated: ${dateStr}</p>
        </div>

        <div style="display: flex; justify-content: space-between; margin-bottom: 40px;">
             <div style="text-align: center; width: 30%; background: #f8f9fa; padding: 15px; border-radius: 8px;">
                <h3 style="color: #dc3545; font-size: 32px; margin: 0;">${vulns.length}</h3>
                <span style="display: block; font-size: 12px; text-transform: uppercase;">Unique Vulns</span>
             </div>
             <div style="text-align: center; width: 30%; background: #f8f9fa; padding: 15px; border-radius: 8px;">
                <h3 style="color: #0d6efd; font-size: 32px; margin: 0;">${data.urls_scanned || 0}</h3>
                <span style="display: block; font-size: 12px; text-transform: uppercase;">Pages Scanned</span>
             </div>
             <div style="text-align: center; width: 30%; background: #f8f9fa; padding: 15px; border-radius: 8px;">
                <h3 style="color: #0dcaf0; font-size: 32px; margin: 0;">${durationDisplay}</h3>
                <span style="display: block; font-size: 12px; text-transform: uppercase;">Duration</span>
             </div>
        </div>

        <div style="margin-bottom: 20px;">
            <h3 style="border-bottom: 1px solid #ddd; padding-bottom: 10px; margin-bottom: 15px;">Vulnerability Findings</h3>
            <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <thead>
                    <tr style="background-color: #f1f1f1; text-align: left;">
                        <th style="padding: 10px; border-bottom: 2px solid #ddd;">Type</th>
                        <th style="padding: 10px; border-bottom: 2px solid #ddd;">URL</th>
                        <th style="padding: 10px; border-bottom: 2px solid #ddd;">Parameter</th>
                        <th style="padding: 10px; border-bottom: 2px solid #ddd;">Conf.</th>
                    </tr>
                </thead>
                <tbody>
                    ${vulns
                      .map(
                        (v) => `
                        <tr style="border-bottom: 1px solid #eee;">
                            <td style="padding: 10px; color: #d63384; font-weight: bold;">${escapeHtml(v.type)}</td>
                            <td style="padding: 10px; word-break: break-all; max-width: 300px;">${escapeHtml(v.url)}</td>
                            <td style="padding: 10px;"><code>${escapeHtml(v.parameter)}</code></td>
                            <td style="padding: 10px;">${v.confidence}%</td>
                        </tr>
                    `,
                      )
                      .join("")}
                    ${vulns.length === 0 ? '<tr><td colspan="4" style="text-align:center; padding: 20px;">No vulnerabilities found.</td></tr>' : ""}
                </tbody>
            </table>
        </div>

        <div style="margin-top: 50px; text-align: center; font-size: 10px; color: #999;">
            <p>Generated by VScan - Advanced Security Scanner</p>
        </div>
    `;

  // Append to body temporarily
  // FIX: html2canvas requires the element to be "visible" in the viewport.
  // We use fixed positioning with a low z-index to hide it behind the main content.
  printContainer.style.position = "fixed";
  printContainer.style.top = "0";
  printContainer.style.left = "0";
  printContainer.style.width = "100%";
  printContainer.style.zIndex = "-9999";
  printContainer.style.backgroundColor = "white"; // Ensure valid background
  document.body.appendChild(printContainer);

  const opt = {
    margin: 0.5,
    filename: `VScan_Report_Fixed_${new Date().getTime()}.pdf`,
    image: { type: "jpeg", quality: 0.98 },
    html2canvas: { scale: 2 },
    jsPDF: { unit: "in", format: "a4", orientation: "portrait" },
  };

  html2pdf()
    .set(opt)
    .from(printContainer)
    .save()
    .then(() => {
      document.body.removeChild(printContainer);
      btn.innerText = originalText;
      btn.disabled = false;
    });
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
