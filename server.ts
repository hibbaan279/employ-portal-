import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import dotenv from "dotenv";
import crypto from "node:crypto";
import Groq from "groq-sdk";
import { db, initDatabase, hashPassword, verifyPassword } from "./server/db";

dotenv.config();

// Initialize the embedded SQLite Database
initDatabase();

let aiClient: Groq | null = null;
function getAiClient(): Groq | null {
  if (!aiClient) {
    const apiKey = process.env.GROQ_API_KEY;
    if (apiKey) {
      aiClient = new Groq({ apiKey });
    }
  }
  return aiClient;
}

// Session token generator
function createSession(userId: string): string {
  const token = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  const expiresAt = now + 30 * 24 * 60 * 60 * 1000; // 30 days
  const stmt = db.prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)");
  stmt.run(token, userId, now, expiresAt);
  return token;
}

// Middleware to authenticate Bearer token
function getAuthUser(req: express.Request): any | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  const token = authHeader.substring(7);
  const now = Date.now();
  const session = db.prepare("SELECT user_id, expires_at FROM sessions WHERE token = ?").get(token) as { user_id: string; expires_at: number } | undefined;
  
  if (!session || session.expires_at < now) {
    return null;
  }

  const user = db.prepare("SELECT id as uid, email, display_name as displayName, role FROM users WHERE id = ?").get(session.user_id);
  return user || null;
}

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  app.use(express.json());

  // ----------------------------------------------------
  // Authentication & User Management APIs
  // ----------------------------------------------------

  // Register
  app.post("/api/auth/register", (req, res) => {
    try {
      const { email, password, displayName, role } = req.body;
      if (!email || !password || !displayName) {
        return res.status(400).json({ error: "Email, password, and display name are required." });
      }

      const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email.toLowerCase());
      if (existing) {
        return res.status(409).json({ error: "An account with this email already exists." });
      }

      const userId = "usr_" + crypto.randomUUID().replace(/-/g, "").substring(0, 12);
      const { hash, salt } = hashPassword(password);
      const userRole = role === "Manager" ? "Manager" : "Employee";
      const now = Date.now();

      db.prepare(`
        INSERT INTO users (id, email, password_hash, salt, display_name, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(userId, email.toLowerCase(), hash, salt, displayName.trim(), userRole, now);

      const token = createSession(userId);
      const user = { uid: userId, email: email.toLowerCase(), displayName: displayName.trim(), role: userRole };

      return res.json({ user, token });
    } catch (err: any) {
      console.error("Register error:", err);
      return res.status(500).json({ error: err.message || "Failed to register account" });
    }
  });

  // Login
  app.post("/api/auth/login", (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
      }

      const row = db.prepare("SELECT id as uid, email, password_hash, salt, display_name as displayName, role FROM users WHERE email = ?").get(email.toLowerCase()) as any;
      if (!row) {
        return res.status(401).json({ error: "Invalid email or password." });
      }

      const isValid = verifyPassword(password, row.password_hash, row.salt);
      if (!isValid) {
        return res.status(401).json({ error: "Invalid email or password." });
      }

      const token = createSession(row.uid);
      const user = { uid: row.uid, email: row.email, displayName: row.displayName, role: row.role };

      return res.json({ user, token });
    } catch (err: any) {
      console.error("Login error:", err);
      return res.status(500).json({ error: err.message || "Failed to log in" });
    }
  });

  // 1-Click Demo Login
  app.post("/api/auth/demo-login", (req, res) => {
    try {
      const { role } = req.body;
      const targetRole = role === "Manager" ? "Manager" : "Employee";
      
      let user = db.prepare("SELECT id as uid, email, display_name as displayName, role FROM users WHERE role = ? LIMIT 1").get(targetRole) as any;
      
      if (!user) {
        // Fallback to first user
        user = db.prepare("SELECT id as uid, email, display_name as displayName, role FROM users LIMIT 1").get() as any;
      }

      if (!user) {
        return res.status(404).json({ error: "No demo user found." });
      }

      const token = createSession(user.uid);
      return res.json({ user, token });
    } catch (err: any) {
      console.error("Demo login error:", err);
      return res.status(500).json({ error: err.message || "Failed demo login" });
    }
  });

  // Get Current User
  app.get("/api/auth/me", (req, res) => {
    const user = getAuthUser(req);
    if (!user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    return res.json({ user });
  });

  // Update Profile
  app.put("/api/auth/profile", (req, res) => {
    const authUser = getAuthUser(req);
    if (!authUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { displayName, role } = req.body;
    const updates: string[] = [];
    const params: any[] = [];

    if (displayName) {
      updates.push("display_name = ?");
      params.push(displayName.trim());
    }
    if (role && (role === "Manager" || role === "Employee")) {
      updates.push("role = ?");
      params.push(role);
    }

    if (updates.length > 0) {
      params.push(authUser.uid);
      db.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).run(...params);
    }

    const updated = db.prepare("SELECT id as uid, email, display_name as displayName, role FROM users WHERE id = ?").get(authUser.uid);
    return res.json({ user: updated });
  });

  // Delete Account
  app.delete("/api/auth/account", (req, res) => {
    const authUser = getAuthUser(req);
    if (!authUser) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    try {
      const uid = authUser.uid;
      // Delete user's sessions
      db.prepare("DELETE FROM sessions WHERE user_id = ?").run(uid);
      // Remove memberships
      db.prepare("DELETE FROM project_members WHERE user_id = ? OR email = ?").run(uid, authUser.email);
      // Unassign tasks or projects
      db.prepare("UPDATE tasks SET assignee_id = '' WHERE assignee_id = ?").run(uid);
      db.prepare("UPDATE projects SET assignee_id = NULL WHERE assignee_id = ?").run(uid);
      // Delete user profile
      db.prepare("DELETE FROM users WHERE id = ?").run(uid);

      return res.json({ success: true, message: "Account deleted successfully" });
    } catch (err: any) {
      console.error("Delete account error:", err);
      return res.status(500).json({ error: err.message || "Failed to delete account" });
    }
  });

  // List all users
  app.get("/api/users", (req, res) => {
    try {
      const rows = db.prepare("SELECT id as uid, email, display_name as displayName, role FROM users ORDER BY display_name ASC").all();
      return res.json(rows);
    } catch (err: any) {
      console.error("Fetch users error:", err);
      return res.status(500).json({ error: err.message });
    }
  });

  // ----------------------------------------------------
  // Projects APIs
  // ----------------------------------------------------

  app.get("/api/projects", (req, res) => {
    try {
      const rows = db.prepare(`
        SELECT id, name, description, owner_id as ownerId, status, assignee_id as assigneeId, deadline, created_at as createdAt, updated_at as updatedAt
        FROM projects
        ORDER BY created_at DESC
      `).all();
      return res.json(rows);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/projects", (req, res) => {
    try {
      const { id, name, description, ownerId, status, assigneeId, deadline } = req.body;
      const now = Date.now();
      const projId = id || "proj_" + crypto.randomUUID().replace(/-/g, "").substring(0, 12);

      db.prepare(`
        INSERT INTO projects (id, name, description, owner_id, status, assignee_id, deadline, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        projId,
        name || "Untitled Project",
        description || "",
        ownerId || "",
        status || "active",
        assigneeId || null,
        deadline || null,
        now,
        now
      );

      const created = db.prepare(`
        SELECT id, name, description, owner_id as ownerId, status, assignee_id as assigneeId, deadline, created_at as createdAt, updated_at as updatedAt
        FROM projects WHERE id = ?
      `).get(projId);

      return res.json(created);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.put("/api/projects/:id", (req, res) => {
    try {
      const { id } = req.params;
      const { name, description, status, assigneeId, deadline } = req.body;
      const now = Date.now();

      const existing = db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as any;
      if (!existing) {
        return res.status(404).json({ error: "Project not found" });
      }

      const updatedName = name !== undefined ? name : existing.name;
      const updatedDesc = description !== undefined ? description : existing.description;
      const updatedStatus = status !== undefined ? status : existing.status;
      const updatedAssignee = assigneeId !== undefined ? (assigneeId === "" ? null : assigneeId) : existing.assignee_id;
      const updatedDeadline = deadline !== undefined ? (deadline === "" ? null : deadline) : existing.deadline;

      db.prepare(`
        UPDATE projects
        SET name = ?, description = ?, status = ?, assignee_id = ?, deadline = ?, updated_at = ?
        WHERE id = ?
      `).run(updatedName, updatedDesc, updatedStatus, updatedAssignee, updatedDeadline, now, id);

      const result = db.prepare(`
        SELECT id, name, description, owner_id as ownerId, status, assignee_id as assigneeId, deadline, created_at as createdAt, updated_at as updatedAt
        FROM projects WHERE id = ?
      `).get(id);

      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.delete("/api/projects/:id", (req, res) => {
    try {
      const { id } = req.params;
      db.prepare("DELETE FROM tasks WHERE project_id = ?").run(id);
      db.prepare("DELETE FROM project_members WHERE project_id = ?").run(id);
      db.prepare("DELETE FROM projects WHERE id = ?").run(id);
      return res.json({ success: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // ----------------------------------------------------
  // Project Members & Invitations APIs
  // ----------------------------------------------------

  app.get("/api/projects/:id/members", (req, res) => {
    try {
      const { id } = req.params;
      const rows = db.prepare(`
        SELECT id, project_id as projectId, user_id as userId, email, role, status, created_at as createdAt
        FROM project_members
        WHERE project_id = ?
        ORDER BY created_at ASC
      `).all(id);
      return res.json(rows);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/projects/:id/members", (req, res) => {
    try {
      const { id: projectId } = req.params;
      const { id, userId, email, role, status } = req.body;
      const now = Date.now();
      const memberId = id || `${projectId}_${userId || email}`;

      db.prepare(`
        INSERT OR REPLACE INTO project_members (id, project_id, user_id, email, role, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(memberId, projectId, userId || "", email.toLowerCase(), role || "member", status || "pending", now);

      const created = db.prepare(`
        SELECT id, project_id as projectId, user_id as userId, email, role, status, created_at as createdAt
        FROM project_members WHERE id = ?
      `).get(memberId);

      return res.json(created);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.put("/api/members/:id", (req, res) => {
    try {
      const { id } = req.params;
      const { role, status, userId } = req.body;
      const existing = db.prepare("SELECT * FROM project_members WHERE id = ?").get(id) as any;
      if (!existing) {
        return res.status(404).json({ error: "Member not found" });
      }

      const updatedRole = role !== undefined ? role : existing.role;
      const updatedStatus = status !== undefined ? status : existing.status;
      const updatedUserId = userId !== undefined ? userId : existing.user_id;

      db.prepare(`
        UPDATE project_members
        SET role = ?, status = ?, user_id = ?
        WHERE id = ?
      `).run(updatedRole, updatedStatus, updatedUserId, id);

      const result = db.prepare(`
        SELECT id, project_id as projectId, user_id as userId, email, role, status, created_at as createdAt
        FROM project_members WHERE id = ?
      `).get(id);

      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.delete("/api/members/:id", (req, res) => {
    try {
      const { id } = req.params;
      db.prepare("DELETE FROM project_members WHERE id = ?").run(id);
      return res.json({ success: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/my-invitations", (req, res) => {
    try {
      const authUser = getAuthUser(req);
      if (!authUser) {
        return res.json([]);
      }
      const rows = db.prepare(`
        SELECT id, project_id as projectId, user_id as userId, email, role, status, created_at as createdAt
        FROM project_members
        WHERE (user_id = ? OR email = ?) AND status = 'pending'
      `).all(authUser.uid, authUser.email.toLowerCase());
      return res.json(rows);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // ----------------------------------------------------
  // Tasks APIs
  // ----------------------------------------------------

  app.get("/api/tasks", (req, res) => {
    try {
      const rows = db.prepare(`
        SELECT id, project_id as projectId, title, description, assignee_id as assigneeId, creator_id as creatorId, status, priority, deadline, created_at as createdAt, updated_at as updatedAt
        FROM tasks
        ORDER BY created_at DESC
      `).all();
      return res.json(rows);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/tasks", (req, res) => {
    try {
      const { id, projectId, title, description, assigneeId, creatorId, status, priority, deadline } = req.body;
      const now = Date.now();
      const taskId = id || "task_" + crypto.randomUUID().replace(/-/g, "").substring(0, 12);

      db.prepare(`
        INSERT INTO tasks (id, project_id, title, description, assignee_id, creator_id, status, priority, deadline, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        taskId,
        projectId,
        title || "Untitled Task",
        description || "",
        assigneeId || "",
        creatorId || "",
        status || "todo",
        priority || "medium",
        deadline || null,
        now,
        now
      );

      const created = db.prepare(`
        SELECT id, project_id as projectId, title, description, assignee_id as assigneeId, creator_id as creatorId, status, priority, deadline, created_at as createdAt, updated_at as updatedAt
        FROM tasks WHERE id = ?
      `).get(taskId);

      return res.json(created);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.put("/api/tasks/:id", (req, res) => {
    try {
      const { id } = req.params;
      const { title, description, assigneeId, status, priority, deadline } = req.body;
      const now = Date.now();

      const existing = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as any;
      if (!existing) {
        return res.status(404).json({ error: "Task not found" });
      }

      const updatedTitle = title !== undefined ? title : existing.title;
      const updatedDesc = description !== undefined ? description : existing.description;
      const updatedAssignee = assigneeId !== undefined ? (assigneeId === "" ? null : assigneeId) : existing.assignee_id;
      const updatedStatus = status !== undefined ? status : existing.status;
      const updatedPriority = priority !== undefined ? priority : existing.priority;
      const updatedDeadline = deadline !== undefined ? (deadline === "" ? null : deadline) : existing.deadline;

      db.prepare(`
        UPDATE tasks
        SET title = ?, description = ?, assignee_id = ?, status = ?, priority = ?, deadline = ?, updated_at = ?
        WHERE id = ?
      `).run(updatedTitle, updatedDesc, updatedAssignee, updatedStatus, updatedPriority, updatedDeadline, now, id);

      const result = db.prepare(`
        SELECT id, project_id as projectId, title, description, assignee_id as assigneeId, creator_id as creatorId, status, priority, deadline, created_at as createdAt, updated_at as updatedAt
        FROM tasks WHERE id = ?
      `).get(id);

      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  app.delete("/api/tasks/:id", (req, res) => {
    try {
      const { id } = req.params;
      db.prepare("DELETE FROM tasks WHERE id = ?").run(id);
      return res.json({ success: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  });

  // ----------------------------------------------------
  // AI Chat & Guidance APIs (with graceful fallbacks)
  // ----------------------------------------------------

  app.post("/api/ai-chat", async (req, res) => {
    try {
      const { message, history, context } = req.body;
      if (!message) {
        return res.status(400).json({ error: "Message is required." });
      }

      const ai = getAiClient();
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("Transfer-Encoding", "chunked");

      if (ai) {
        const systemInstruction = `You are an internal company assistant for an Employee Task & Project Manager tool. 
Your job is to provide guidance, suggest task priorities, and answer questions.
Context about the user and their tasks:
${context || 'No additional context provided.'}
When suggesting a priority for a given task, evaluate its description and deadline, then suggest either 'low', 'medium', or 'high'.
Be helpful, concise, and professional. Mention their tasks by name if relevant. Use markdown format.`;

        const groqMessages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }> = [
          { role: 'system', content: systemInstruction }
        ];

        if (Array.isArray(history)) {
          history.forEach((h: { role: string; text: string }) => {
            if (h.text && (h.role === "user" || h.role === "model")) {
              groqMessages.push({
                role: h.role === "model" ? "assistant" : "user",
                content: h.text
              });
            }
          });
        }

        groqMessages.push({ role: 'user', content: message });

        const stream = await ai.chat.completions.create({
          model: "llama-3.3-70b-versatile",
          messages: groqMessages,
          stream: true,
        });

        for await (const chunk of stream) {
          const text = chunk.choices[0]?.delta?.content || '';
          if (text) res.write(text);
        }
        res.end();
      } else {
        // Fallback guidance when GROQ_API_KEY is not configured
        const fallbackText = `### Task & Project Manager Assistant

Hello! I am your internal portal assistant.

${message.toLowerCase().includes("priority") || message.toLowerCase().includes("prioritize") ? `
**Priority Advice for Your Tasks:**
- Focus first on high-priority items with immediate deadlines.
- Keep in-progress tasks limited to 2-3 at a time to prevent multitasking overhead.
- Group related items by project to maximize focus.
` : `
**How I can help:**
- Review and recommend prioritization for your active tasks.
- Keep track of project milestones and upcoming due dates.
- Organize your daily workflow and delegation.
`}

*(Note: To unlock live AI assistance, set \`GROQ_API_KEY\` in your \`.env\` file).*
`;
        res.write(fallbackText);
        res.end();
      }
    } catch (error: any) {
      console.error("AI Chat API Error:", error);
      if (!res.headersSent) {
        res.status(500).json({ error: error.message || "Failed to generate response" });
      } else {
        res.write("\n\n[Error generating response]");
        res.end();
      }
    }
  });

  app.post("/api/suggest-priority", async (req, res) => {
    try {
      const { title, description, deadline } = req.body;
      const ai = getAiClient();

      if (ai) {
        const prompt = `Based on the following task details, suggest a priority level from strictly one of these options: 'low', 'medium', or 'high'. Reply with ONLY the word 'low', 'medium', or 'high' without any punctuation or other text.
        
        Task Title: ${title || "Untitled"}
        Description: ${description || "No description"}
        Deadline: ${deadline || "None specified"}`;

        const response = await ai.chat.completions.create({
          model: "llama-3.3-70b-versatile",
          messages: [{ role: 'user', content: prompt }],
          max_tokens: 10,
        });

        const priority = response.choices[0]?.message?.content?.trim().toLowerCase();
        res.json({ priority: priority === "high" || priority === "low" || priority === "medium" ? priority : "medium" });
      } else {
        // Smart heuristic fallback
        const combined = `${title} ${description}`.toLowerCase();
        if (combined.includes("urgent") || combined.includes("critical") || combined.includes("asap") || combined.includes("security") || combined.includes("blocker")) {
          return res.json({ priority: "high" });
        }
        if (combined.includes("review") || combined.includes("important") || combined.includes("release")) {
          return res.json({ priority: "medium" });
        }
        return res.json({ priority: "low" });
      }
    } catch (error: any) {
      console.error("Suggest priority error:", error);
      res.status(500).json({ error: error.message || "Failed to suggest priority" });
    }
  });

  // ----------------------------------------------------
  // Vite & Static Asset Handling
  // ----------------------------------------------------

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Independent Platform running on http://localhost:${PORT}`);
  });
}

startServer();
