# Enterprise Employee & Manager Portal (Independent Platform)

A self-contained, full-stack enterprise portal for employee task and project management, featuring an AI guidance assistant, role-based workflows, and real-time dashboard analytics.

## 🚀 Key Features

- **100% Independent & Self-Hosted**: Built-in zero-config SQLite database (`data/portal.db`) powered by Node.js native SQLite engine. Zero external cloud database locks or Firebase configuration required.
- **Native Role-Based Authentication**:
  - Secure email & password registration with cryptographic password hashing (PBKDF2/scrypt) and session token management.
  - Built-in **1-Click Demo Logins** for testing:
    - **Manager**: `manager@company.com` (password: `password123`)
    - **Employee**: `employee@company.com` (password: `password123`)
- **Project & Initiative Management**:
  - Full lifecycle tracking: Active, Completed, Archived.
  - Team member invitations, role delegation (Admin / Member), and acceptance tracking.
  - Native deadline enforcement (Managers set timelines).
- **Kanban Task Board**:
  - 4-stage pipeline: **To Do**, **In Progress**, **Review**, **Completed**.
  - Priority assignment (Low, Medium, High) with smart AI analysis.
  - Assignee filtering and due-date alerts.
- **AI Guidance Assistant**:
  - Real-time streaming assistant for task prioritization, workload suggestions, and summaries.
  - Operates seamlessly with Google Gemini 2.5 (`GEMINI_API_KEY`) and contains intelligent local heuristic fallbacks when offline.

---

## 🛠️ Quick Start

### 1. Prerequisites
- **Node.js**: v22.0.0 or higher (v24 recommended for native `node:sqlite`).

### 2. Install Dependencies
```bash
npm install
```

### 3. (Optional) Configure Gemini API Key
Create a `.env` file in the root directory:
```env
GEMINI_API_KEY=your_gemini_api_key_here
PORT=3000
```
*(Note: If `GEMINI_API_KEY` is not provided, the platform runs normally and the AI assistant provides built-in heuristic guidance).*

### 4. Start the Application
```bash
npm run dev
```

Visit **http://localhost:3000** in your browser.

---

## 📁 Project Structure

```
├── data/                  # Auto-created SQLite database (portal.db)
├── server/
│   └── db.ts              # SQLite database schema, seeding, and session store
├── src/
│   ├── components/        # React components (Layout, AuthProvider, Modals)
│   ├── pages/             # Dashboard, Projects, Tasks, AIGuidance, Login
│   ├── services/          # API services & reactive subscriber bus
│   ├── types.ts           # Shared TypeScript interfaces
│   └── App.tsx            # App router and protected route wrappers
├── server.ts              # Express backend with standalone REST APIs
├── package.json           # Lightweight project dependencies
└── tsconfig.json          # TypeScript configuration
```

---

## 🔒 User Roles & Permissions

| Role | Permissions |
| :--- | :--- |
| **Manager** | Create projects, invite & manage team members, set task/project deadlines, trigger deadline reminders. |
| **Employee** | Create and manage assigned tasks, update task progress/status, collaborate on projects. |
