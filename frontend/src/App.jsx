
import { useState } from "react";
import Login from "./Login";
import Dashboard from "./Dashboard";

export default function App() {
  const [authed, setAuthed] = useState(
    !!localStorage.getItem("token")
  );

  function logout() {
    localStorage.removeItem("token");
    setAuthed(false);
  }

  return authed
    ? <Dashboard onLogout={logout} />
    : <Login onLogin={() => setAuthed(true)} />;
}
