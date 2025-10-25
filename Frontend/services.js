document.addEventListener("DOMContentLoaded", () => {
  const scanNowLink = document.getElementById("scan-now-link");

  if (scanNowLink) {
    scanNowLink.addEventListener("click", async (event) => {
      event.preventDefault(); // Stop the link from doing anything by default

      try {
        // Check the user's login status by calling our API
        const response = await fetch("/api/user");

        if (response.ok) {
          // STATUS 200: User is logged in.
          // Redirect to the scanner page.
          window.location.href = "serviceclassic.html";
        } else {
          // STATUS 401 (or other error): User is not logged in.
          // Redirect to the sign-up page.
          window.location.href = "signin.html";
        }
      } catch (error) {
        console.error("Error checking authentication status:", error);
        // As a fallback, send them to the sign-up page if the API call fails
        window.location.href = "signin.html";
      }
    });
  }
});
