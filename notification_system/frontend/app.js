/**
 * Copyright © 2025 DoctorMen. All Rights Reserved.
 */
// BLEEDING EDGE UI - Interactive Timeline Notification Dashboard
// Master-level JavaScript engineering with security and performance

// Configuration
const API_BASE = 'http://localhost:5000/api';
let authToken = localStorage.getItem('auth_token');
let csrfToken = null;

// Custom Cursor
const cursor = document.querySelector('.custom-cursor');
const cursorFollower = document.querySelector('.cursor-follower');

document.addEventListener('mousemove', (e) => {
    cursor.style.left = e.clientX + 'px';
    cursor.style.top = e.clientY + 'px';
    
    setTimeout(() => {
        cursorFollower.style.left = e.clientX + 'px';
        cursorFollower.style.top = e.clientY + 'px';
    }, 100);
});

// 3D Background with Three.js
function init3DBackground() {
    const canvas = document.getElementById('bg-canvas');
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(window.devicePixelRatio);
    
    // Create particles
    const geometry = new THREE.BufferGeometry();
    const particleCount = 1000;
    const positions = new Float32Array(particleCount * 3);
    
    for (let i = 0; i < particleCount * 3; i++) {
        positions[i] = (Math.random() - 0.5) * 100;
    }
    
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    
    const material = new THREE.PointsMaterial({
        color: 0x667eea,
        size: 0.1,
        transparent: true,
        opacity: 0.6
    });
    
    const particles = new THREE.Points(geometry, material);
    scene.add(particles);
    
    camera.position.z = 30;
    
    // Animation loop
    function animate() {
        requestAnimationFrame(animate);
        
        particles.rotation.x += 0.0005;
        particles.rotation.y += 0.0005;
        
        renderer.render(scene, camera);
    }
    
    animate();
    
    // Handle resize
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
}

// GSAP Animations
function initAnimations() {
    // Animate stats on scroll
    gsap.from('.stat-bubble', {
        scrollTrigger: {
            trigger: '.hero-stats',
            start: 'top 80%'
        },
        y: 50,
        opacity: 0,
        duration: 0.8,
        stagger: 0.2,
        ease: 'power3.out'
    });
    
    // Animate timeline cards
    gsap.from('.timeline-card', {
        scrollTrigger: {
            trigger: '.timeline-cards',
            start: 'top 80%'
        },
        y: 100,
        opacity: 0,
        duration: 1,
        stagger: 0.2,
        ease: 'power3.out'
    });
    
    // Animate feature cards
    gsap.from('.feature-card', {
        scrollTrigger: {
            trigger: '.features-grid',
            start: 'top 80%'
        },
        scale: 0.8,
        opacity: 0,
        duration: 0.8,
        stagger: 0.1,
        ease: 'back.out(1.7)'
    });
}

// Card Tilt Effect
function initTiltEffect() {
    const cards = document.querySelectorAll('[data-tilt]');
    
    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            
            const rotateX = (y - centerY) / 10;
            const rotateY = (centerX - x) / 10;
            
            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.05, 1.05, 1.05)`;
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) scale3d(1, 1, 1)';
        });
    });
}

// API Functions with Security
async function fetchWithAuth(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }
    
    if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
    }
    
    try {
        const response = await fetch(url, {
            ...options,
            headers,
            credentials: 'include'
        });
        
        if (response.status === 401) {
            // Token expired
            authToken = null;
            localStorage.removeItem('auth_token');
            showAuthModal();
            throw new Error('Authentication required');
        }
        
        return response;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

async function getCsrfToken() {
    try {
        const response = await fetch(`${API_BASE}/csrf-token`, {
            credentials: 'include'
        });
        const data = await response.json();
        csrfToken = data.csrf_token;
    } catch (error) {
        console.error('Failed to get CSRF token:', error);
    }
}

async function register(email, password) {
    try {
        showLoading();
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        hideLoading();
        
        if (response.ok) {
            showToast('Registration successful! Please check your email.', 'success');
            // Auto-login after registration
            await login(email, password);
        } else {
            showToast(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        hideLoading();
        showToast('Registration failed. Please try again.', 'error');
    }
}

async function login(email, password) {
    try {
        showLoading();
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        hideLoading();
        
        if (response.ok) {
            authToken = data.token;
            localStorage.setItem('auth_token', authToken);
            await getCsrfToken();
            hideAuthModal();
            showToast('Logged in successfully!', 'success');
        } else {
            showToast(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        hideLoading();
        showToast('Login failed. Please try again.', 'error');
    }
}

async function subscribeToNotification(type) {
    if (!authToken) {
        showAuthModal();
        return;
    }
    
    try {
        showLoading();
        const response = await fetchWithAuth(`${API_BASE}/notifications/subscribe`, {
            method: 'POST',
            body: JSON.stringify({
                type: type,
                frequency: 'all'
            })
        });
        
        const data = await response.json();
        hideLoading();
        
        if (response.ok) {
            showToast('Successfully subscribed to notifications!', 'success');
            updateButtonState(type, true);
        } else {
            showToast(data.error || 'Subscription failed', 'error');
        }
    } catch (error) {
        hideLoading();
        if (error.message !== 'Authentication required') {
            showToast('Subscription failed. Please try again.', 'error');
        }
    }
}

async function unsubscribeFromNotification(type) {
    try {
        showLoading();
        const response = await fetchWithAuth(`${API_BASE}/notifications/unsubscribe`, {
            method: 'POST',
            body: JSON.stringify({ type })
        });
        
        const data = await response.json();
        hideLoading();
        
        if (response.ok) {
            showToast('Unsubscribed successfully', 'success');
            updateButtonState(type, false);
        } else {
            showToast(data.error || 'Unsubscribe failed', 'error');
        }
    } catch (error) {
        hideLoading();
        showToast('Unsubscribe failed. Please try again.', 'error');
    }
}

// UI Functions
function showAuthModal() {
    const modal = document.getElementById('auth-modal');
    modal.style.display = 'block';
    
    // Close modal on click outside
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            hideAuthModal();
        }
    });
}

function hideAuthModal() {
    document.getElementById('auth-modal').style.display = 'none';
}

function showLoading() {
    const loading = document.createElement('div');
    loading.className = 'loading';
    loading.innerHTML = '<div class="spinner"></div>';
    document.body.appendChild(loading);
}

function hideLoading() {
    const loading = document.querySelector('.loading');
    if (loading) {
        loading.remove();
    }
}

function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function updateButtonState(type, subscribed) {
    const button = document.querySelector(`[data-type="${type}"]`);
    if (button) {
        if (subscribed) {
            button.textContent = 'Subscribed ✓';
            button.style.background = 'linear-gradient(135deg, #4CAF50, #45a049)';
        } else {
            button.querySelector('.btn-text').textContent = 'Subscribe';
            button.style.background = 'linear-gradient(135deg, var(--primary), var(--secondary))';
        }
    }
}

// Counter Animation
function animateCounter(element, target) {
    let current = 0;
    const increment = target / 100;
    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            element.textContent = target;
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 20);
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize 3D background
    if (window.THREE) {
        init3DBackground();
    }
    
    // Initialize animations
    if (window.gsap) {
        initAnimations();
    }
    
    // Initialize tilt effect
    initTiltEffect();
    
    // Get CSRF token
    getCsrfToken();
    
    // Subscribe buttons
    document.querySelectorAll('.subscribe-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const type = btn.dataset.type;
            await subscribeToNotification(type);
        });
    });
    
    // Hero CTA button
    document.querySelector('.btn-hero').addEventListener('click', () => {
        if (authToken) {
            showToast('You are already logged in!', 'success');
        } else {
            showAuthModal();
        }
    });
    
    // Register form
    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        // Client-side validation
        if (password.length < 12) {
            showToast('Password must be at least 12 characters', 'error');
            return;
        }
        
        await register(email, password);
    });
    
    // Close modal button
    document.querySelector('.close-modal').addEventListener('click', hideAuthModal);
    
    // Animate stat counters
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const target = parseInt(entry.target.textContent.replace(/[^0-9]/g, ''));
                if (!isNaN(target)) {
                    animateCounter(entry.target, target);
                }
                observer.unobserve(entry.target);
            }
        });
    });
    
    document.querySelectorAll('.stat-value').forEach(stat => {
        observer.observe(stat);
    });
    
    // Parallax effect on scroll
    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        const parallaxElements = document.querySelectorAll('.blob');
        
        parallaxElements.forEach((el, index) => {
            const speed = 0.5 + (index * 0.1);
            el.style.transform = `translateY(${scrolled * speed}px)`;
        });
    });
});

// Security: Clear sensitive data on page unload
window.addEventListener('beforeunload', () => {
    csrfToken = null;
});

// Prevent right-click on sensitive elements (optional)
document.addEventListener('contextmenu', (e) => {
    if (e.target.closest('.glass-card')) {
        // Allow normal behavior
    }
});

// Add keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Esc to close modal
    if (e.key === 'Escape') {
        hideAuthModal();
    }
});

console.log('%c🚀 Timeline Notification System', 'font-size: 24px; color: #667eea; font-weight: bold;');
console.log('%cBleeding Edge UI | Enterprise Security', 'font-size: 14px; color: #4CAF50;');
console.log('%cPowered by Master-Level Engineering', 'font-size: 12px; color: #888;');
