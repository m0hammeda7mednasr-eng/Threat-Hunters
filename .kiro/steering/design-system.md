---
inclusion: always
---

# Threat Hunters Design System Rules

This document defines the design system structure and integration guidelines for the Threat Hunters web application when working with Figma designs.

## Project Overview

- **Framework**: React 19.2.0 with Vite
- **Styling**: CSS Modules (component-scoped CSS files)
- **Icons**: lucide-react + inline SVG
- **State Management**: React Context (ThemeContext)
- **Build Tool**: Vite (rolldown-vite)

## Design Tokens

### Location
Design tokens are defined in `src/styles/colors.css` using CSS custom properties.

### Token Structure
```css
:root, :root[data-theme="dark"] {
  /* Primary Colors */
  --primary-100: #6d7cff;
  --primary-80: #7384ff;
  --primary-60: #8aa3ff;
  
  /* Background Colors */
  --bg-primary: #0d0b1d;
  --bg-card: rgba(26, 29, 53, 0.55);
  
  /* Typography */
  --text-primary: #ffffff;
  --text-secondary: #9ca3af;
  
  /* Borders */
  --border-primary: rgba(109, 124, 255, 0.36);
  
  /* Shadows */
  --shadow-primary: 0 10px 30px rgba(109, 124, 255, 0.42);
}

:root[data-theme="light"] {
  /* Light mode overrides */
  --primary-100: #155dfc;
  --bg-primary: #ededed;
  --text-primary: #0f172a;
}
```

### Token Categories
- **Primary Colors**: `--primary-{100|80|60|40|20}`
- **Accent Colors**: `--accent-{coral|red|yellow|green}`
- **Backgrounds**: `--bg-{primary|secondary|tertiary|card}`
- **Typography**: `--text-{primary|secondary|tertiary|button}`
- **Borders**: `--border-{primary|secondary}`, `--{component}-border`
- **Shadows**: `--shadow-{primary|lg}`, `--{component}-shadow`
- **Gradients**: `--button-gradient`, `--hero-card-bg`, `--icon-gradient`

## Component Architecture

### Component Structure
Components follow a co-located pattern:
```
src/components/
├── ComponentName.jsx
└── ComponentName.css
```

### Component Patterns
```jsx
// Functional component with memo optimization
import { memo } from 'react';
import './ComponentName.css';

const ComponentName = ({ prop1, prop2 }) => {
  return (
    <div className="component-name">
      {/* Component content */}
    </div>
  );
};

export default memo(ComponentName);
```

### Navigation Pattern
Components receive navigation callbacks as props:
```jsx
const Component = ({ 
  onNavigateToSignUp, 
  onNavigateToHome, 
  onNavigateToBlog,
  onNavigateToAwareness,
  onNavigateToTools 
}) => {
  // Use callbacks for navigation
};
```

## Styling Approach

### CSS Methodology
- **Scoped CSS**: Each component has its own CSS file
- **BEM-like naming**: `.component-name`, `.component-name__element`, `.component-name--modifier`
- **CSS Variables**: All colors, spacing, and effects use CSS custom properties
- **Responsive**: Mobile-first with `@media` queries

### Common Patterns

#### Card Components
```css
.card-name {
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: 16px;
  padding: 2rem;
  transition: all 0.3s ease;
}

.card-name:hover {
  transform: translateY(-4px);
  box-shadow: var(--shadow-primary);
}
```

#### Buttons
```css
.btn-primary {
  padding: 0.65rem 1.5rem;
  background: linear-gradient(135deg, var(--primary-100) 0%, var(--primary-80) 100%);
  color: var(--text-button);
  border: none;
  border-radius: 10px;
  font-weight: 500;
  cursor: pointer;
  transition: transform 0.2s, box-shadow 0.3s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--button-shadow-hover);
}
```

#### Responsive Breakpoints
```css
@media (max-width: 768px) {
  /* Mobile styles */
}

@media (max-width: 480px) {
  /* Small mobile styles */
}
```

## Icon System

### Icon Sources
1. **lucide-react**: Primary icon library
2. **Inline SVG**: Custom icons and logos

### Icon Usage Pattern
```jsx
// Inline SVG (preferred for custom icons)
<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="..." stroke="currentColor" strokeWidth="2" 
        strokeLinecap="round" strokeLinejoin="round"/>
</svg>

// lucide-react (for standard icons)
import { Shield, Search, AlertTriangle } from 'lucide-react';
<Shield size={24} />
```

### Icon Styling
```css
.icon-wrapper {
  width: 48px;
  height: 48px;
  background: var(--icon-gradient);
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-button);
}

.icon-wrapper svg {
  width: 24px;
  height: 24px;
}
```

## Theme System

### Theme Context
Located in `src/context/ThemeContext.jsx`:
```jsx
const { theme, toggleTheme } = useTheme();
// theme: 'dark' | 'light'
```

### Theme Implementation
- Theme is stored in `data-theme` attribute on `:root`
- CSS variables automatically switch based on theme
- Backdrop filters disabled in light mode for performance

## Asset Management

### Asset Locations
- **Public Assets**: `public/` (vite.svg)
- **Component Assets**: `src/assets/` (react.svg)

### Asset References
```jsx
// Public assets
<img src="/vite.svg" alt="Vite" />

// Component assets
import reactLogo from './assets/react.svg';
<img src={reactLogo} alt="React" />
```

## Project Structure

```
threat-hunters-app/
├── src/
│   ├── components/          # All React components
│   │   ├── Navbar.jsx
│   │   ├── Navbar.css
│   │   ├── HomePage.jsx
│   │   └── HomePage.css
│   ├── context/            # React Context providers
│   │   └── ThemeContext.jsx
│   ├── styles/             # Global styles
│   │   └── colors.css      # Design tokens
│   ├── assets/             # Static assets
│   ├── App.jsx             # Main app component
│   ├── App.css             # App-level styles
│   ├── main.jsx            # Entry point
│   └── index.css           # Global CSS reset
├── public/                 # Public assets
├── package.json
└── vite.config.js
```

## Figma Integration Guidelines

### When Converting Figma Designs

1. **Replace Tailwind with CSS Variables**
   - Convert Tailwind utilities to CSS custom properties
   - Use existing design tokens from `colors.css`
   - Match spacing and sizing to existing patterns

2. **Component Reuse**
   - Check for existing components before creating new ones
   - Reuse button styles, card patterns, icon wrappers
   - Follow existing navigation patterns

3. **Styling Consistency**
   - Use component-scoped CSS files (`.jsx` + `.css`)
   - Follow BEM-like naming conventions
   - Apply hover states and transitions consistently
   - Use `memo()` for performance optimization

4. **Visual Parity**
   - Match border-radius (typically 10px-16px)
   - Use gradient backgrounds for primary actions
   - Apply consistent shadows and hover effects
   - Maintain responsive breakpoints at 768px and 480px

5. **Theme Support**
   - Ensure all colors use CSS variables
   - Test in both light and dark modes
   - Disable backdrop-filter in light mode if needed

6. **Icons**
   - Prefer inline SVG for custom icons
   - Use lucide-react for standard icons
   - Maintain consistent icon sizing (20px-24px typical)
   - Apply `currentColor` for stroke/fill

### Code Connect Workflow

When mapping Figma components to code:
1. Identify the component in `src/components/`
2. Note the component name and file path
3. Use the Figma power's `add_code_connect_map` tool
4. Specify framework as "React" and language as "javascript"

### Example Mapping
```
Figma Component: "Primary Button"
Code Location: src/components/Navbar.jsx
Component Name: btn-signup (CSS class) or Navbar (React component)
Framework: React
```
