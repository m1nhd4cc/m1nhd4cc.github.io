document.addEventListener('DOMContentLoaded', function() {

    // ======================================================
    // THEME TOGGLE (LIGHT/DARK MODE)
    // ======================================================
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    const body = document.body;

    function applySavedTheme() {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            body.classList.add('dark-mode');
            themeToggleBtn.innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            body.classList.remove('dark-mode');
            themeToggleBtn.innerHTML = '<i class="fas fa-moon"></i>';
        }
    }

    themeToggleBtn.addEventListener('click', () => {
        body.classList.toggle('dark-mode');
        if (body.classList.contains('dark-mode')) {
            localStorage.setItem('theme', 'dark');
            themeToggleBtn.innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            localStorage.setItem('theme', 'light');
            themeToggleBtn.innerHTML = '<i class="fas fa-moon"></i>';
        }
    });

    applySavedTheme();

    // ======================================================
    // LIVE SEARCH FUNCTIONALITY
    // ======================================================
    const searchBtn = document.getElementById('search-btn');
    const searchInput = document.getElementById('search-input');
    const searchableItems = document.querySelectorAll('.searchable-item');

    searchBtn.addEventListener('click', () => {
        searchInput.classList.toggle('active');
        searchInput.focus();
    });

    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        searchableItems.forEach(item => {
            const itemText = item.textContent.toLowerCase();
            if (itemText.includes(searchTerm)) {
                item.classList.remove('hide');
            } else {
                item.classList.add('hide');
            }
        });
    });

    // ======================================================
    // SMOOTH SCROLLING & ACTIVE NAV LINK
    // ======================================================
    const navLinks = document.querySelectorAll('.main-nav a');
    navLinks.forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });

    const sections = document.querySelectorAll('section[id]');
    window.addEventListener('scroll', () => {
        let current = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            if (pageYOffset >= sectionTop - 75) {
                current = section.getAttribute('id');
            }
        });
        
        navLinks.forEach(a => {
            a.classList.remove('active');
            if (a.getAttribute('href').substring(1) === current) {
                a.classList.add('active');
            }
        });
    });

    // ======================================================
    // TYPING EFFECT
    // ======================================================
    const typingElement = document.querySelector('.typing-effect');
    if (typingElement) {
        const roles = ["Security Engineer..", "Future SOC Analyst - Incident Response ^^", "CTF Player.."];
        let roleIndex = 0, charIndex = 0, isDeleting = false;

        function type() {
            const currentRole = roles[roleIndex];
            const typeSpeed = isDeleting ? 100 : 150;
            
            if (isDeleting) typingElement.textContent = currentRole.substring(0, charIndex-- - 1);
            else typingElement.textContent = currentRole.substring(0, charIndex++ + 1);

            if (!isDeleting && charIndex === currentRole.length) setTimeout(() => isDeleting = true, 2000);
            else if (isDeleting && charIndex === 0) { isDeleting = false; roleIndex = (roleIndex + 1) % roles.length; }
            
            setTimeout(type, typeSpeed);
        }
        type();
    }
});
