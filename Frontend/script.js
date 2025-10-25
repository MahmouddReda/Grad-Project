document.addEventListener("DOMContentLoaded", () => {
  // This function runs as soon as the page is loaded
  const prefillForm = () => {
    // 1. Get the query parameters from the page's URL
    const params = new URLSearchParams(window.location.search);

    // 2. Get the values for each field
    const firstName = params.get("firstname");
    const lastName = params.get("lastname");
    const email = params.get("email");

    // 3. Find the input fields on the page
    const firstNameInput = document.getElementById("floatingFirstname");
    const lastNameInput = document.getElementById("floatingLastname");
    const emailInput = document.getElementById("floatingInput");

    // 4. Set the input values if they exist in the URL
    if (firstName && firstNameInput) {
      firstNameInput.value = firstName;
    }
    if (lastName && lastNameInput) {
      lastNameInput.value = lastName;
    }
    if (email && emailInput) {
      emailInput.value = email;
    }
  };

  // Call the function to pre-fill the form
  prefillForm();
});
document.getElementById("signupForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  const body = Object.fromEntries(formData.entries());

  const response = await fetch("/signin", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (response.ok) {
    // After a successful signup, redirect to the homepage.
    // auth.js will then run and show the "Hello, <name>" message.
    window.location.href = "serviceclassic.html";
  } else {
    const error = await response.json();
    alert(error.error || "Signup failed");
  }
});
