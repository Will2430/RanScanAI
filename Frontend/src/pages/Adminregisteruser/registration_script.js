/**
 * RanScanAI Professional Registration Portal
 * Handles multi-step form, validation, and API integration
 */

// Disable browser scroll restoration so we control it on load
if ('scrollRestoration' in history) {
    history.scrollRestoration = 'manual';
}

// Configuration
const API_BASE_URL = 'http://localhost:8000';
const CURRENT_STEP = { value: 1 };
const TOTAL_STEPS = 2;

// Form cache
const form = document.getElementById('registrationForm');
const successMessage = document.getElementById('successMessage');
const errorMessage = document.getElementById('errorMessage');
const loadingOverlay = document.getElementById('loadingOverlay');
const passwordInput = document.getElementById('password');

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('Registration Portal Loaded');
    
    // Reset form and scroll to top on every page load/refresh
    form.reset();
    CURRENT_STEP.value = 1;
    document.querySelectorAll('.error-message').forEach(el => el.classList.remove('show'));
    document.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
    // Double requestAnimationFrame ensures scroll runs after browser restoration
    requestAnimationFrame(() => requestAnimationFrame(() => window.scrollTo(0, 0)));
    
    // Setup event listeners
    form.addEventListener('submit', handleFormSubmit);
    form.addEventListener('change', validateField);
    passwordInput.addEventListener('input', updatePasswordStrength);
    
    // Initialize
    updateProgressBar();
    updateStepDisplay();
    initCountryDropdown();
});

// Warn user before refresh/close if form has data
window.addEventListener('beforeunload', (e) => {
    if (isFormDirty()) {
        e.preventDefault();
        e.returnValue = '';
    }
});

function isFormDirty() {
    const fields = ['firstName', 'lastName', 'email', 'phone', 'username', 'password'];
    return fields.some(id => {
        const el = document.getElementById(id);
        return el && el.value.trim() !== '';
    });
}

// ============================================================================
// Country Code Picker
// ============================================================================

const COUNTRIES = [
    { flag: '🇲🇾', name: 'Malaysia',        code: '+60'  },
    { flag: '🇸🇬', name: 'Singapore',       code: '+65'  },
    { flag: '🇺🇸', name: 'United States',   code: '+1'   },
    { flag: '🇬🇧', name: 'United Kingdom',  code: '+44'  },
    { flag: '🇦🇺', name: 'Australia',       code: '+61'  },
    { flag: '🇯🇵', name: 'Japan',           code: '+81'  },
    { flag: '🇰🇷', name: 'South Korea',     code: '+82'  },
    { flag: '🇨🇳', name: 'China',           code: '+86'  },
    { flag: '🇮🇳', name: 'India',           code: '+91'  },
    { flag: '🇮🇩', name: 'Indonesia',       code: '+62'  },
    { flag: '🇹🇭', name: 'Thailand',        code: '+66'  },
    { flag: '🇵🇭', name: 'Philippines',     code: '+63'  },
    { flag: '🇻🇳', name: 'Vietnam',         code: '+84'  },
    { flag: '🇭🇰', name: 'Hong Kong',       code: '+852' },
    { flag: '🇹🇼', name: 'Taiwan',          code: '+886' },
    { flag: '🇫🇷', name: 'France',          code: '+33'  },
    { flag: '🇩🇪', name: 'Germany',         code: '+49'  },
    { flag: '🇦🇪', name: 'United Arab Emirates', code: '+971' },
    { flag: '🇸🇦', name: 'Saudi Arabia',    code: '+966' },
    { flag: '🇧🇷', name: 'Brazil',          code: '+55'  },
    { flag: '🇨🇦', name: 'Canada',          code: '+1'   },
    { flag: '🇳🇿', name: 'New Zealand',     code: '+64'  },
    { flag: '🇵🇰', name: 'Pakistan',        code: '+92'  },
    { flag: '🇧🇩', name: 'Bangladesh',      code: '+880' },
    { flag: '🇱🇰', name: 'Sri Lanka',       code: '+94'  },
    { flag: '🇲🇲', name: 'Myanmar',         code: '+95'  },
    { flag: '🇰🇭', name: 'Cambodia',        code: '+855' },
    { flag: '🇱🇦', name: 'Laos',            code: '+856' },
    { flag: '🇧🇳', name: 'Brunei',          code: '+673' },
    { flag: '🇲🇴', name: 'Macau',           code: '+853' },
];

let filteredCountries = [...COUNTRIES];

function initCountryDropdown() {
    renderCountryList(COUNTRIES);

    // Close when clicking outside
    document.addEventListener('click', (e) => {
        const picker = document.getElementById('countryPicker');
        if (picker && !picker.contains(e.target)) {
            closeCountryDropdown();
        }
    });
}

function renderCountryList(list) {
    const ul = document.getElementById('countryPickerList');
    const currentCode = document.getElementById('countryCode').value;
    if (!ul) return;

    if (list.length === 0) {
        ul.innerHTML = '<li class="no-results">No countries found</li>';
        return;
    }

    ul.innerHTML = list.map(c =>
        `<li class="${c.code === currentCode ? 'active' : ''}" onclick="selectCountry('${c.code}', '${c.flag} ${c.code}')">
            <span>${c.flag}</span>
            <span>${c.name}</span>
            <span class="dial-code">${c.code}</span>
        </li>`
    ).join('');
}

function toggleCountryDropdown() {
    const dropdown = document.getElementById('countryPickerDropdown');
    const isOpen = dropdown.classList.contains('open');
    if (isOpen) {
        closeCountryDropdown();
    } else {
        // Position relative to button using fixed coordinates
        const btn = document.getElementById('countryPickerBtn');
        const rect = btn.getBoundingClientRect();
        dropdown.style.top = (rect.bottom + 4) + 'px';
        dropdown.style.left = rect.left + 'px';
        dropdown.classList.add('open');
        const search = document.getElementById('countrySearch');
        search.value = '';
        filterCountries();
        setTimeout(() => search.focus(), 50);
    }
}

function closeCountryDropdown() {
    const dropdown = document.getElementById('countryPickerDropdown');
    if (dropdown) dropdown.classList.remove('open');
}

function filterCountries() {
    const query = document.getElementById('countrySearch').value.toLowerCase().trim();
    filteredCountries = COUNTRIES.filter(c =>
        c.name.toLowerCase().includes(query) || c.code.includes(query)
    );
    renderCountryList(filteredCountries);
}

function selectCountry(code, display) {
    document.getElementById('countryCode').value = code;
    document.getElementById('countryPickerDisplay').textContent = display;
    closeCountryDropdown();
}

// ============================================================================
// Multi-Step Form Navigation
// ============================================================================

function nextStep() {
    if (validateCurrentStep()) {
        if (CURRENT_STEP.value < TOTAL_STEPS) {
            CURRENT_STEP.value++;
            updateStepDisplay();
        }
    }
}

function previousStep() {
    if (CURRENT_STEP.value > 1) {
        CURRENT_STEP.value--;
        updateStepDisplay();
    }
}

function updateStepDisplay() {
    // Hide all steps
    document.querySelectorAll('.form-step').forEach(step => {
        step.classList.remove('active');
    });
    
    // Show current step
    document.querySelector(`.form-step[data-step="${CURRENT_STEP.value}"]`).classList.add('active');
    
    // Update buttons
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const submitBtn = document.getElementById('submitBtn');
    
    prevBtn.style.display = CURRENT_STEP.value > 1 ? 'flex' : 'none';
    nextBtn.style.display = CURRENT_STEP.value < TOTAL_STEPS ? 'flex' : 'none';
    submitBtn.style.display = CURRENT_STEP.value === TOTAL_STEPS ? 'flex' : 'none';
    
    // Update progress
    updateProgressBar();
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function updateProgressBar() {
    const progress = (CURRENT_STEP.value / TOTAL_STEPS) * 100;
    document.getElementById('progressFill').style.width = progress + '%';
    document.getElementById('currentStep').textContent = CURRENT_STEP.value;
}

function validateCurrentStep() {
    const fieldsToValidate = {
        1: ['firstName', 'lastName', 'email', 'phone'],
        2: ['username', 'password', 'confirmPassword']
    };
    
    const fields = fieldsToValidate[CURRENT_STEP.value];
    let isValid = true;
    
    fields.forEach(fieldId => {
        const validator = getValidatorForField(fieldId);
        if (validator && !validator()) {
            isValid = false;
        }
    });
    
    return isValid;
}

// ============================================================================
// Field Validation
// ============================================================================

function validateField(e) {
    const fieldId = e.target.id;
    const validator = getValidatorForField(fieldId);
    if (validator) {
        validator();
    }
}

function getValidatorForField(fieldId) {
    const validators = {
        firstName: validateFirstName,
        lastName: validateLastName,
        email: validateEmail,
        username: validateUsername,
        password: validatePassword,
        confirmPassword: validateConfirmPassword,
        phone: validatePhone
    };
    return validators[fieldId];
}

function validateFirstName() {
    const value = document.getElementById('firstName').value.trim();
    
    if (!value) {
        showError('firstName', 'First name is required');
        return false;
    }
    if (value.length < 2 || value.length > 50) {
        showError('firstName', 'First name must be 2-50 characters');
        return false;
    }
    if (!/^[a-zA-Z\s\-']+$/.test(value)) {
        showError('firstName', 'First name can only contain letters, spaces, hyphens, and apostrophes');
        return false;
    }
    clearError('firstName');
    return true;
}

function validateLastName() {
    const value = document.getElementById('lastName').value.trim();
    
    if (!value) {
        showError('lastName', 'Last name is required');
        return false;
    }
    if (value.length < 2 || value.length > 50) {
        showError('lastName', 'Last name must be 2-50 characters');
        return false;
    }
    if (!/^[a-zA-Z\s\-']+$/.test(value)) {
        showError('lastName', 'Last name can only contain letters, spaces, hyphens, and apostrophes');
        return false;
    }
    clearError('lastName');
    return true;
}

function validateEmail() {
    const value = document.getElementById('email').value.trim().toLowerCase();
    
    if (!value) {
        showError('email', 'Email is required');
        return false;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(value)) {
        showError('email', 'Please enter a valid email address');
        return false;
    }
    clearError('email');
    return true;
}

function validatePhone() {
    const value = document.getElementById('phone').value.trim();
    
    if (!value) {
        clearError('phone');
        return true; // Optional
    }
    
    const phoneRegex = /^[\d\s\-]+$/;
    if (!phoneRegex.test(value) || value.replace(/\D/g, '').length < 7 || value.replace(/\D/g, '').length > 15) {
        showError('phone', 'Please enter a valid phone number (7-15 digits)');
        return false;
    }
    clearError('phone');
    return true;
}

function validateUsername() {
    const value = document.getElementById('username').value.trim();
    
    if (!value) {
        showError('username', 'Username is required');
        return false;
    }
    if (value.length < 3 || value.length > 20) {
        showError('username', 'Username must be 3-20 characters');
        return false;
    }
    if (!/^[a-zA-Z0-9_]+$/.test(value)) {
        showError('username', 'Username can only contain letters, numbers, and underscores');
        return false;
    }
    clearError('username');
    return true;
}

function validatePassword() {
    const value = document.getElementById('password').value;
    
    if (!value) {
        showError('password', 'Password is required');
        return false;
    }
    if (value.length < 8) {
        showError('password', 'Password must be at least 8 characters');
        return false;
    }
    if (!/[A-Z]/.test(value)) {
        showError('password', 'Password must contain uppercase letter');
        return false;
    }
    if (!/[a-z]/.test(value)) {
        showError('password', 'Password must contain lowercase letter');
        return false;
    }
    if (!/[0-9]/.test(value)) {
        showError('password', 'Password must contain number');
        return false;
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(value)) {
        showError('password', 'Password must contain special character');
        return false;
    }
    clearError('password');
    return true;
}

function validateConfirmPassword() {
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (!confirmPassword) {
        showError('confirmPassword', 'Please confirm your password');
        return false;
    }
    if (password !== confirmPassword) {
        showError('confirmPassword', 'Passwords do not match');
        return false;
    }
    clearError('confirmPassword');
    return true;
}

function showError(fieldId, message) {
    const errorElement = document.getElementById(fieldId + 'Error');
    const inputElement = document.getElementById(fieldId);
    
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.classList.add('show');
    }
    if (inputElement) {
        inputElement.classList.add('error');
    }
}

function clearError(fieldId) {
    const errorElement = document.getElementById(fieldId + 'Error');
    const inputElement = document.getElementById(fieldId);
    
    if (errorElement) {
        errorElement.classList.remove('show');
        errorElement.textContent = '';
    }
    if (inputElement) {
        inputElement.classList.remove('error');
    }
}

// ============================================================================
// Password Strength & Role Description
// ============================================================================

function updatePasswordStrength() {
    const password = passwordInput.value;
    const strengthContainer = document.getElementById('passwordStrength');
    
    if (!password) {
        strengthContainer.innerHTML = '';
        return;
    }
    
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) strength++;
    
    let strengthClass = 'weak';
    let strengthText = 'Weak';
    
    if (strength >= 3) {
        strengthClass = 'fair';
        strengthText = 'Fair';
    }
    if (strength >= 4) {
        strengthClass = 'good';
        strengthText = 'Good';
    }
    if (strength >= 5) {
        strengthClass = 'strong';
        strengthText = 'Strong';
    }
    
    let html = `<div class="password-strength-text">${strengthText}</div><div class="password-strength ${strengthClass}">`;
    for (let i = 0; i < 4; i++) {
        html += '<div class="password-strength-bar"></div>';
    }
    html += '</div>';
    
    strengthContainer.innerHTML = html;
}

// ============================================================================
// Form Submission
// ============================================================================

async function handleFormSubmit(e) {
    e.preventDefault();
    
    console.log('Form submission started');
    
    if (!validateAllFields()) {
        console.log('Validation failed');
        return;
    }
    
    showLoading(true);
    document.getElementById('submitBtn').disabled = true;
    
    try {
        const formData = {
            first_name: document.getElementById('firstName').value.trim(),
            last_name: document.getElementById('lastName').value.trim(),
            email: document.getElementById('email').value.trim().toLowerCase(),
            username: document.getElementById('username').value.trim(),
            password: document.getElementById('password').value,
            phone_number: getFullPhoneNumber() || null,
            role: 'user'
        };
        
        console.log('Submitting registration data');
        
        const response = await fetch(`${API_BASE_URL}/api/auth/admin/create-user`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getAuthToken()}`
            },
            body: JSON.stringify(formData)
        });
        
        const responseData = await response.json();
        
        if (!response.ok) {
            throw new Error(responseData.detail || 'Registration failed');
        }
        
        console.log('Registration successful');
        showSuccess(
            'User account created successfully!',
            `Username: ${formData.username}\nEmail: ${formData.email}\nRole: User`
        );
        
        form.reset();
        CURRENT_STEP.value = 1;
        document.querySelectorAll('.error-message').forEach(el => el.classList.remove('show'));
        document.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
        
        setTimeout(() => {
            updateStepDisplay();
        }, 2000);
        
    } catch (error) {
        console.error('Registration error:', error);
        showErrorMessage(error.message || 'Registration failed. Please try again.');
    } finally {
        showLoading(false);
        document.getElementById('submitBtn').disabled = false;
    }
}

function validateAllFields() {
    return validateFirstName() && 
           validateLastName() && 
           validateEmail() && 
           validateUsername() && 
           validatePassword() && 
           validateConfirmPassword();
}

// ============================================================================
// Message Display
// ============================================================================

function showSuccess(title, details) {
    errorMessage.style.display = 'none';
    document.getElementById('successText').textContent = title;
    document.getElementById('successDetail').textContent = details;
    successMessage.style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showErrorMessage(message) {
    successMessage.style.display = 'none';
    document.getElementById('errorText').textContent = message;
    errorMessage.style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function closeMessage(elementId) {
    document.getElementById(elementId).style.display = 'none';
}

function showLoading(show) {
    loadingOverlay.style.display = show ? 'flex' : 'none';
}

// ============================================================================
// Utility Functions
// ============================================================================

function togglePasswordVisibility(fieldId) {
    const field = document.getElementById(fieldId);
    field.type = field.type === 'password' ? 'text' : 'password';
}

function getFullPhoneNumber() {
    const phone = document.getElementById('phone').value.trim();
    if (!phone) return '';
    const countryCode = document.getElementById('countryCode').value;
    return countryCode + phone.replace(/^0+/, ''); // strip leading zero
}

function getAuthToken() {
    return localStorage.getItem('authToken') || sessionStorage.getItem('authToken') || '';
}
