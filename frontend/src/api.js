
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8000"
});

// Automatically attach the logged-in user's JWT.
api.interceptors.request.use((cfg) => {
  const token = localStorage.getItem("token");

  if (token) {
    cfg.headers.Authorization = `Bearer ${token}`;
  }

  return cfg;
});

// If a saved token expires, remove it and return to login.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (
      error.response?.status === 401 &&
      localStorage.getItem("token")
    ) {
      localStorage.removeItem("token");
      window.location.reload();
    }

    return Promise.reject(error);
  }
);

export default api;
