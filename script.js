// Dark/Light Mode Toggle
const toggle = document.getElementById("toggleTheme");
toggle.addEventListener("click", () => {
  document.body.classList.toggle("light");
  document.body.classList.toggle("dark");
  toggle.textContent = document.body.classList.contains("dark") ? "🌙" : "☀️";
});

// Smooth Scroll for Navbar
document.querySelectorAll('nav a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function(e) {
      e.preventDefault();
      document.querySelector(this.getAttribute('href')).scrollIntoView({
          behavior: 'smooth'
      });
  });
});
