async function checkAuthState() {
  const authContainer = document.getElementById("auth-container");
  if (!authContainer) return;

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
    } else {
      // ---- THIS IS THE UPDATED PART ----
      // User is not logged in, so explicitly set the HTML for Login/Sign-up buttons.
      authContainer.innerHTML = `
        <button type="button" class="btn btn-outline-light me-2" onclick="window.location.href = 'login.html';">Login</button>
        <button type="button" class="btn btn-light" onclick="window.location.href = 'signin.html';">Sign-up</button>
      `;
    }
  } catch (error) {
    console.error("Error checking auth state:", error);
    // Optionally, you can set the default buttons here as a fallback in case of a network error
    authContainer.innerHTML = `
      <button type="button" class="btn btn-outline-light me-2" onclick="window.location.href = 'login.html';">Login</button>
      <button type="button" class="btn btn-light" onclick="window.location.href = 'signin.html';">Sign-up</button>
    `;
  }
}

// Run the check as soon as the page content is loaded
document.addEventListener("DOMContentLoaded", checkAuthState);
