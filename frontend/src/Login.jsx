
import { useState } from "react";
import api from "./api";

export default function Login({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState("");

  async function submit(e) {
    e.preventDefault();
    setError("");

    try {
      const isLogin = mode === "login";

      const body = isLogin
        ? { email, password }
        : { email, password, org_name: orgName };

      const { data } = await api.post(
        isLogin ? "/auth/login" : "/auth/register",
        body
      );

      localStorage.setItem("token", data.access_token);
      onLogin();

    } catch (err) {
      const detail = err.response?.data?.detail;

      setError(
        typeof detail === "string"
          ? detail
          : "Invalid input or server unreachable"
      );
    }
  }

  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <h1>SentinelAI</h1>

        <p className="muted">
          {mode === "login"
            ? "Sign in"
            : "Create your organization"}
        </p>

        {mode === "register" && (
          <input
            placeholder="Organization name"
            value={orgName}
            onChange={(e) => setOrgName(e.target.value)}
            required
          />
        )}

        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />

        <input
          type="password"
          placeholder="Password (10+ characters)"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        {error && <p className="error">{error}</p>}

        <button type="submit">
          {mode === "login" ? "Sign in" : "Register"}
        </button>

        <a
          href="#"
          onClick={(e) => {
            e.preventDefault();
            setMode(mode === "login" ? "register" : "login");
            setError("");
          }}
        >
          {mode === "login"
            ? "Need an account? Register"
            : "Have an account? Sign in"}
        </a>
      </form>
    </div>
  );
}
