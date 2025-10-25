document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault(); // prevent default browser submit

  const formData = new FormData(e.target);
  const body = Object.fromEntries(formData.entries());

  const response = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (response.ok) {
    // Login was successful, redirect to the homepage
    // The auth.js script on the homepage will then show the "Hello, [Name]" message
    window.location.href = "index.html";
  } else {
    // Login failed, show the error message from the server
    const errorData = await response.json();
    alert(errorData.error || "Login failed");
  }
});
