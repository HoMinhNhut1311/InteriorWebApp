import { createContext, useEffect, useState } from "react";
import Swal from "sweetalert2";

const UserContext = createContext();

export const UserProvider = ({ children }) => {
  const [token, setToken] = useState(JSON.parse(sessionStorage.getItem("token")));

  useEffect(() => {
    setToken(sessionStorage.getItem("token"));
  }, [token]);

  const login = (tokenData) => {
    setToken(tokenData);
    sessionStorage.setItem("token", JSON.stringify(tokenData.token));
  };
  const logout = async () => {
    await Swal.fire({
      title: "Đăng xuất thành công",
      text: `Tự động chuyển sang trang Đăng Nhập sau 2 giây nữa`,
      timer: 2000,
      timerProgressBar: true,
      background: "#36d7b7",
      color: "white",
      icon: "info",
    })
      .then
      // () => {
      //     navi("/login")
      // }
      ();
    sessionStorage.removeItem("token");
    setToken(null);
  };

  return (
    <UserContext.Provider value={{ token, login, logout}}>
      {children}
    </UserContext.Provider>
  );
};

export default UserContext;
