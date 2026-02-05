# Илья & Аня — Wedding Invitation Template

A romantic, premium wedding invitation website in modern Italian (Tuscany) style.

## Design Philosophy

- **Aesthetic**: Tuscany villa atmosphere with soft southern light
- **Mood**: Cinematic, elegant, gentle — premium but minimal
- **Feel**: High-end wedding/fashion magazine editorial

## Color Palette

| Color | Hex | Usage |
|-------|-----|-------|
| Ivory | `#FAF8F5` | Primary background |
| Milk | `#FFFEFB` | Secondary background |
| Cream | `#F5F2ED` | Gradient transitions |
| Warm Beige | `#D4CBC0` | Decorative elements |
| Olive | `#7A8B6E` | Primary accent |
| Olive Dark | `#5C6B52` | Hover states |
| Gold (subtle) | `rgba(201, 169, 98, 0.15)` | Soft accents |

## Typography

- **Headings & Names**: Cormorant Garamond (serif, elegant)
- **Body**: Raleway (sans-serif, modern, clean)

## Structure

1. **Hero Section** — Names with romantic subtitle
2. **Intro Section** — Emotional, intimate message
3. **Details Section** — Location, date, format, duration
4. **Visual Section** — Photography placeholders with quotes
5. **Closing Section** — Warm farewell message

## Customization

### Text Content
All Russian text is clearly marked and easy to replace:
- Couple names in `.hero-names`
- Dates in `.hero-date` and `.detail-value`
- Location in `.detail-value`
- Messages in `.intro-text` and `.closing-text`

### Images
Replace the `.image-placeholder` divs with actual `<img>` tags:

```html
<!-- Replace this: -->
<div class="image-placeholder">
    <span class="image-placeholder-text">Фотография</span>
</div>

<!-- With this: -->
<img src="your-image.jpg" alt="Description">
```

### Colors
All colors are defined as CSS variables in `:root` for easy customization.

## Framer Integration

### Method 1: Code Component
1. Copy the entire HTML into a Framer Code Component
2. The CSS is embedded and self-contained
3. Replace placeholder images with Framer image components

### Method 2: Visual Recreation
Use the CSS variables and structure as reference:

1. **Typography Stack**:
   - Import Cormorant Garamond + Raleway from Google Fonts
   
2. **Section Padding**:
   - Desktop: 120-160px vertical
   - Mobile: 60-80px vertical
   
3. **Animations to Apply**:
   - Fade-up on scroll (40px travel, 0.8s duration)
   - Gentle parallax on images (0.3 speed factor)
   - Hover lift on cards (+4px translateY)

4. **Breakpoints**:
   - Mobile: 480px
   - Tablet: 768px
   - Desktop: 1200px

### Framer-Specific Tips

1. **Scroll Animations**: Use Framer's built-in "While in View" animations
2. **Parallax**: Apply with Framer's scroll-linked transforms
3. **Typography**: Set up text styles matching the CSS values
4. **Spacing**: Use Framer's auto-layout with the specified gaps

## Animation Timing

| Animation | Duration | Easing |
|-----------|----------|--------|
| Fade In | 1.2s | ease-out |
| Fade Up | 1.0s | ease-out |
| Hover Lift | 0.4s | ease-out |
| Page Load | 0.6s | ease-out |

## Accessibility Notes

- High contrast text on backgrounds
- Semantic HTML structure
- Smooth scroll with `prefers-reduced-motion` respect (add if needed)
- Alt text placeholders for images

## Browser Support

- Modern browsers (Chrome, Safari, Firefox, Edge)
- Mobile Safari / Chrome
- CSS Grid + Flexbox layout

---

*Designed with love for Илья & Аня*
