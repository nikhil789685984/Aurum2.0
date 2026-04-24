# AURUM - Ultra-Premium Fine Dining & Delivery Platform ✦

AURUM is a highly advanced, full-stack restaurant management and online dining platform. It features an interactive, animated, and luxurious frontend combined with a robust Node.js and MongoDB backend.

## 🌟 Key Features

* **Premium UI/UX:** Custom cursors, smooth scroll reveals, parallax effects, and a responsive modern design mimicking a 3-Michelin-star experience.
* **Secure Authentication:** OTP and Password-based secure login system with cross-site cookies and strict auth guards.
* **Advanced Reservation System:** Real-time table booking with validation and email confirmations.
* **Delivery & Interactive Cart:** 100+ premium dishes curated by top Indian chefs, a seamless cart drawer, and live delivery location tracking.
* **Event Ticketing System:** Browse 60+ exclusive celebrity events, pay a 50% advance securely via Razorpay, and automatically receive an Ultra-Premium PDF ticket via email.
* **Custom Table Builder:** Interactively mix and match from 50+ dishes and 45+ fine wines to curate a personalized dining experience.
* **Live Admin Dashboard:** Real-time Server-Sent Events (SSE) tracking revenue, users, orders, and event signups. One-click status management, and real-time MongoDB database connection.
* **User Profiles:** Dedicated "My Account" page allowing users to track their order history, reservations, and event tickets.
* **AI Gym Coach:** Integrated OpenAI chatbot for tailored fitness and nutrition advice right on the platform.

## 🛠️ Tech Stack

* **Frontend:** HTML5, CSS3, Vanilla JavaScript
* **Backend:** Node.js, Express.js
* **Database:** MongoDB Atlas (Cloud Database)
* **Payments:** Stripe, Razorpay
* **Email & Documents:** Nodemailer, Resend API, PDFKit
* **Deployment:** GitHub Pages (Frontend), Render (Backend)

## 🚀 Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/nikhil789685984/Aurum2.0.git
   cd Aurum2.0
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up Environment Variables:**
   Rename `.env.example` to `.env` and fill in your API keys (MongoDB, Stripe, Razorpay, Resend, etc.):
   ```env
   PORT=3000
   NODE_ENV=development
   MONGODB_URI=your_mongodb_connection_string
   STRIPE_SECRET_KEY=your_stripe_key
   RAZORPAY_KEY_ID=your_razorpay_id
   RAZORPAY_KEY_SECRET=your_razorpay_secret
   RESEND_API_KEY=your_resend_api_key
   # ... add other required keys
   ```

4. **Run the server:**
   ```bash
   npm start
   ```

5. **Open in Browser:**
   Navigate to `http://localhost:3000` to view the website.

---
*© 2025 AURUM Fine Dining Ltd. Crafted with passion.*