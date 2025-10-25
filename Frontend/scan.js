zdocument.getElementById("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = document.getElementById("website-url").value;
  const resultsContainer = document.getElementById("results-container");

  // Show a loading message
  resultsContainer.innerHTML = `
    <div class="d-flex justify-content-center">
      <div class="spinner-border" role="status">
        <span class="visually-hidden">Loading...</span>
      </div>
      <p class="ms-3">Scanning... This may take a moment.</p>
    </div>
  `;

  try {
    const response = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || "Scan failed");
    }

    const results = await response.json();
    displayResults(results);
  } catch (error) {
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

  let html = `
    <h2 class="pb-2 border-bottom">Scan Results</h2>
    <p><strong>Target:</strong> ${data.target}</p>
    <p><strong>URLs Scanned:</strong> ${data.urls_scanned}</p>
  `;

  if (data.vulnerabilities && data.vulnerabilities.length > 0) {
    html += `
      <h3 class="mt-4">Vulnerabilities Found (${data.vulnerabilities.length}):</h3>
      <table class="table table-striped">
        <thead>
          <tr>
            <th>Type</th>
            <th>URL</th>
            <th>Payload</th>
          </tr>
        </thead>
        <tbody>
    `;
    data.vulnerabilities.forEach((vuln) => {
      html += `
        <tr>
          <td>${vuln.type}</td>
          <td><code>${vuln.url}</code></td>
          <td><code>${vuln.payload}</code></td>
        </tr>
      `;
    });
    html += `</tbody></table>`;
  } else {
    html += `<div class="alert alert-success mt-4">No vulnerabilities found.</div>`;
  }

  resultsContainer.innerHTML = html;
}
