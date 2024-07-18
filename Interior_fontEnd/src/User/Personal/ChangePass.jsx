import { useContext, useEffect, useState } from "react";
import UserContext from "../../Context/userContext";
import { changePass } from "../../Data/User/userApi";
import Swal from "sweetalert2";
import { useNavigate } from "react-router-dom";

function ChangePassword() {
  const [captcha, setCaptcha] = useState("");
  const [text, setText] = useState("");
  const { token, setToken } = useContext(UserContext);
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [cfPw, setCfPw] = useState("");
  const [msg, setMsg] = useState("");
  const navi = useNavigate();

  useEffect(() => {
    generateCaptcha();
  }, [token]);
  function randomText(length) {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
  const logout = () => {
    navi("/login");
    sessionStorage.removeItem("token");
    setToken(null);
  };
  function generateCaptcha(e) {
    if (e) {
      e.preventDefault();
    }
    const canvas = document.getElementById("captcha");
    const context = canvas.getContext("2d");
    context.clearRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = "#f2f2f2";
    context.fillRect(0, 0, canvas.width, canvas.height);

    const text = randomText(6);
    context.font = "32px Arial";
    context.fillStyle = "#000000";
    context.fillText(text, 10, 40);
    setText(text);
    for (let i = 0; i < 10; i++) {
      context.beginPath();
      context.moveTo(
        Math.random() * canvas.width,
        Math.random() * canvas.height
      );
      context.lineTo(
        Math.random() * canvas.width,
        Math.random() * canvas.height
      );
      context.stroke();
    }

    for (let i = 0; i < 100; i++) {
      context.beginPath();
      context.arc(
        Math.random() * canvas.width,
        Math.random() * canvas.height,
        1,
        0,
        2 * Math.PI
      );
      context.fill();
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    console.log("Handle submit called");

    if (text === captcha) {
      if (newPw !== cfPw) {
        setMsg("Mật khẩu mới và mật khẩu xác nhận không khớp");
        Swal.fire({
          title: "Lỗi",
          text: "Mật khẩu mới và mật khẩu xác nhận không khớp",
          icon: "error",
        });
        return;
      } else {
        try {
          const response = await changePass(
            { pwOld: oldPw, pwNew: newPw },
            token
          );
          setMsg("Đổi mật thành công");
          Swal.fire({
            title: "Success",
            text: "Đổi mật thành công, vui lòng đăng nhập lại!",
            icon: "success",
          });
        } catch (error) {
          setMsg("Đổi mật khẩu thất bại");
          Swal.fire({
            title: "Lỗi",
            text: `"Đổi mật khẩu thất bại"`,
            icon: "error",
          });
          console.error("Error changing password:", error);
        }
      }
    } else {
      setMsg("Mã captcha không khớp");
      Swal.fire({
        title: "Lỗi",
        text: "Mã captcha không khớp",
        icon: "error",
      });
    }
  };
  return (
    <div className="formbold-main-wrapper">
      <div className="formbold-form-container d-flex border border-2">
        <form className="formr" onSubmit={handleSubmit}>
          <div className="flex-columnr">
            <label>Nhập mập khẩu cũ</label>
          </div>
          <div className="inputFormr">
            <svg
              height={20}
              viewBox="-64 0 512 512"
              width={20}
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="m336 512h-288c-26.453125 0-48-21.523438-48-48v-224c0-26.476562 21.546875-48 48-48h288c26.453125 0 48 21.523438 48 48v224c0 26.476562-21.546875 48-48 48zm-288-288c-8.8125 0-16 7.167969-16 16v224c0 8.832031 7.1875 16 16 16h288c8.8125 0 16-7.167969 16-16v-224c0-8.832031-7.1875-16-16-16zm0 0" />
              <path d="m304 224c-8.832031 0-16-7.167969-16-16v-80c0-52.929688-43.070312-96-96-96s-96 43.070312-96 96v80c0 8.832031-7.167969 16-16 16s-16-7.167969-16-16v-80c0-70.59375 57.40625-128 128-128s128 57.40625 128 128v80c0 8.832031-7.167969 16-16 16zm0 0" />
            </svg>
            <input
              type="password"
              className="inputr"
              placeholder="Nhập mật khẩu cũ"
              value={oldPw}
              onChange={(e) => setOldPw(e.target.value)}
              required
            />
          </div>
          <div className="flex-columnr">
            <label>Nhập mật khẩu mới</label>
          </div>
          <div className="inputFormr">
            <svg
              height={20}
              viewBox="-64 0 512 512"
              width={20}
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="m336 512h-288c-26.453125 0-48-21.523438-48-48v-224c0-26.476562 21.546875-48 48-48h288c26.453125 0 48 21.523438 48 48v224c0 26.476562-21.546875 48-48 48zm-288-288c-8.8125 0-16 7.167969-16 16v224c0 8.832031 7.1875 16 16 16h288c8.8125 0 16-7.167969 16-16v-224c0-8.832031-7.1875-16-16-16zm0 0" />
              <path d="m304 224c-8.832031 0-16-7.167969-16-16v-80c0-52.929688-43.070312-96-96-96s-96 43.070312-96 96v80c0 8.832031-7.167969 16-16 16s-16-7.167969-16-16v-80c0-70.59375 57.40625-128 128-128s128 57.40625 128 128v80c0 8.832031-7.167969 16-16 16zm0 0" />
            </svg>
            <input
              type="password"
              className="inputr"
              placeholder="Nhập mật khẩu mới"
              title="Tối thiếu 6 kí tự có ít nhất 1 chữ hoa và 1 số"
              pattern="^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$"
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              required
            />
            <svg
              viewBox="0 0 576 512"
              height="1em"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="M288 32c-80.8 0-145.5 36.8-192.6 80.6C48.6 156 17.3 208 2.5 243.7c-3.3 7.9-3.3 16.7 0 24.6C17.3 304 48.6 356 95.4 399.4C142.5 443.2 207.2 480 288 480s145.5-36.8 192.6-80.6c46.8-43.5 78.1-95.4 93-131.1c3.3-7.9 3.3-16.7 0-24.6c-14.9-35.7-46.2-87.7-93-131.1C433.5 68.8 368.8 32 288 32zM144 256a144 144 0 1 1 288 0 144 144 0 1 1 -288 0zm144-64c0 35.3-28.7 64-64 64c-7.1 0-13.9-1.2-20.3-3.3c-5.5-1.8-11.9 1.6-11.7 7.4c.3 6.9 1.3 13.8 3.2 20.7c13.7 51.2 66.4 81.6 117.6 67.9s81.6-66.4 67.9-117.6c-11.1-41.5-47.8-69.4-88.6-71.1c-5.8-.2-9.2 6.1-7.4 11.7c2.1 6.4 3.3 13.2 3.3 20.3z" />
            </svg>
          </div>
          <div className="flex-columnr">
            <label>Nhập lại mật khẩu</label>
          </div>
          <div className="inputFormr">
            <svg
              height={20}
              viewBox="-64 0 512 512"
              width={20}
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="m336 512h-288c-26.453125 0-48-21.523438-48-48v-224c0-26.476562 21.546875-48 48-48h288c26.453125 0 48 21.523438 48 48v224c0 26.476562-21.546875 48-48 48zm-288-288c-8.8125 0-16 7.167969-16 16v224c0 8.832031 7.1875 16 16 16h288c8.8125 0 16-7.167969 16-16v-224c0-8.832031-7.1875-16-16-16zm0 0" />
              <path d="m304 224c-8.832031 0-16-7.167969-16-16v-80c0-52.929688-43.070312-96-96-96s-96 43.070312-96 96v80c0 8.832031-7.167969 16-16 16s-16-7.167969-16-16v-80c0-70.59375 57.40625-128 128-128s128 57.40625 128 128v80c0 8.832031-7.167969 16-16 16zm0 0" />
            </svg>
            <input
              type="password"
              className="inputr"
              placeholder="Nhập lại mật khẩu"
              title="Tối thiếu 6 kí tự có ít nhất 1 chữ hoa và 1 số"
              pattern="^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$"
              value={cfPw}
              onChange={(e) => setCfPw(e.target.value)}
              required
            />
            <svg
              viewBox="0 0 576 512"
              height="1em"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="M288 32c-80.8 0-145.5 36.8-192.6 80.6C48.6 156 17.3 208 2.5 243.7c-3.3 7.9-3.3 16.7 0 24.6C17.3 304 48.6 356 95.4 399.4C142.5 443.2 207.2 480 288 480s145.5-36.8 192.6-80.6c46.8-43.5 78.1-95.4 93-131.1c3.3-7.9 3.3-16.7 0-24.6c-14.9-35.7-46.2-87.7-93-131.1C433.5 68.8 368.8 32 288 32zM144 256a144 144 0 1 1 288 0 144 144 0 1 1 -288 0zm144-64c0 35.3-28.7 64-64 64c-7.1 0-13.9-1.2-20.3-3.3c-5.5-1.8-11.9 1.6-11.7 7.4c.3 6.9 1.3 13.8 3.2 20.7c13.7 51.2 66.4 81.6 117.6 67.9s81.6-66.4 67.9-117.6c-11.1-41.5-47.8-69.4-88.6-71.1c-5.8-.2-9.2 6.1-7.4 11.7c2.1 6.4 3.3 13.2 3.3 20.3z" />
            </svg>
          </div>
          <div className="flex-columnr">
            <label>Nhập mã captcha</label>
          </div>
          <div className="inputFormr">
            <svg
              height={20}
              viewBox="-64 0 512 512"
              width={20}
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="m336 512h-288c-26.453125 0-48-21.523438-48-48v-224c0-26.476562 21.546875-48 48-48h288c26.453125 0 48 21.523438 48 48v224c0 26.476562-21.546875 48-48 48zm-288-288c-8.8125 0-16 7.167969-16 16v224c0 8.832031 7.1875 16 16 16h288c8.8125 0 16-7.167969 16-16v-224c0-8.832031-7.1875-16-16-16zm0 0" />
              <path d="m304 224c-8.832031 0-16-7.167969-16-16v-80c0-52.929688-43.070312-96-96-96s-96 43.070312-96 96v80c0 8.832031-7.167969 16-16 16s-16-7.167969-16-16v-80c0-70.59375 57.40625-128 128-128s128 57.40625 128 128v80c0 8.832031-7.167969 16-16 16zm0 0" />
            </svg>
            <input
              type="text"
              className="inputr"
              placeholder="Nhập mã captcha"
              value={captcha}
              onChange={(e) => setCaptcha(e.target.value)}
              required
            />
            <canvas id="captcha" width="150" height="50"></canvas>
            <button onClick={(e) => generateCaptcha(e)} width="120" height="50">
              Generate CAPTCHA
            </button>
          </div>
          <div className="w-50"></div>
          <button className="button-submitr">Đổi mật khẩu</button>
        </form>
      </div>
    </div>
  );
}
export default ChangePassword;
