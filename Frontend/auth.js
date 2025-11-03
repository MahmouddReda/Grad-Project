async function checkAuthState() {
  const authContainer = document.getElementById("auth-container");
  const signupBlock = document.getElementById("homepage-signup-block");
  const loggedinBlock = document.getElementById("homepage-loggedin-block");
  const userFirstNameSpan = document.getElementById("user-firstname");

  if (!authContainer) {
    console.warn("Auth container not found. Header cannot be updated.");
  }

  try {
    const response = await fetch("/api/user");

    if (response.ok) {
      const { user } = await response.json();
      // User is logged in, show the personalized greeting.
      authContainer.innerHTML = `
      <div class="dropdown text-end"> 
        <a href="#" class="d-block link-secondary text-light text-decoration-none dropdown-toggle show" data-bs-toggle="dropdown" aria-expanded="true"> 
            Hello, ${user.firstname}
        </a> 
        <ul class="dropdown-menu dropdown-menu-dark dropdown-menu-end text-small shadoww">
            <li><a class="dropdown-item" href="#">Profile</a></li>
            <li><a class="dropdown-item" href="#">Settings</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item" href="/logout">Logout</a></li>
        </ul> 
      </div>
      `;
      if (signupBlock) signupBlock.style.display = "none";
      if (loggedinBlock) loggedinBlock.style.display = "block"; // Make logged-in content visible

      // 3. Populate the first name in the logged-in block (if it exists)
      if (userFirstNameSpan) {
        userFirstNameSpan.textContent = user.firstname; // Set the text content
      }
    } else {
      // --- USER IS NOT LOGGED IN ---

      // 1. Update the header
      if (authContainer) {
        authContainer.innerHTML = `
            <button type="button" class="btn btn-outline-light me-2" onclick="window.location.href = 'login.html';">Login</button>
            <button type="button" class="btn btn-light" onclick="window.location.href = 'signin.html';">Sign-up</button>
          `;
      }

      // 2. Show signup block, hide logged-in block (if they exist)
      if (signupBlock) signupBlock.style.display = ""; // Reset to default display
      if (loggedinBlock) loggedinBlock.style.display = "none"; // Make sure logged-in content is hidden

      // Clear the name span if it exists (optional, but good practice)
      if (userFirstNameSpan) {
        userFirstNameSpan.textContent = "";
      }
    }
  } catch (error) {
    console.error("Error checking auth state:", error);
    // Fallback: Show Login/Signup buttons in header
    if (authContainer) {
      authContainer.innerHTML = `
          <button type="button" class="btn btn-outline-light me-2" onclick="window.location.href = 'login.html';">Login</button>
          <button type="button" class="btn btn-light" onclick="window.location.href = 'signin.html';">Sign-up</button>
        `;
    }
    // Fallback: Ensure signup block is visible, logged-in block is hidden
    if (signupBlock) signupBlock.style.display = "";
    if (loggedinBlock) loggedinBlock.style.display = "none";
    if (userFirstNameSpan) userFirstNameSpan.textContent = ""; // Clear name on error too
  }
}

// Run the check as soon as the page content is loaded
document.addEventListener("DOMContentLoaded", checkAuthState);
