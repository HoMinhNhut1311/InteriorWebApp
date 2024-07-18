import { useState } from "react";
import { registerApi } from "../../Data/User/userApi";
import Swal from "sweetalert2";
import { useNavigate } from "react-router-dom";

function Register() {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    roleNames: ["USER"],
  });
  const [errors, setErrors] = useState({});
  const [onload, setOnLoad] = useState(false);
  const navi = useNavigate("");
  const validate = () => {
    const errors = {};
    if (!formData.username) {
      errors.username = "Username is required";
    } else if (formData.username.length < 3) {
      errors.username = "Username phải có ít nhất 3 kí tự";
    }
    if (!formData.email) {
      errors.email = "Email is required";
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      errors.email = "Email address is invalid";
    }
    return errors;
  };

  const handleRegister = async (event) => {
    event.preventDefault();
    const validationErrors = validate();
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }
    setOnLoad(true);
    console.log(formData);
    const response = await registerApi(formData);
    if (response.status === 200) {
      console.log(response.data);
      Swal.fire({
        title: "Đăng ký thành công",
        text: `Mật khẩu đã được gửi đến ${formData.email}`,
        icon: "success",
      }).then(()=>{
            navi("/login")
      }).finally(() => {
        setOnLoad(false);
      });
    } else {
      Swal.fire({
        title: response.data.message,
        text: `Mã lỗi : ${response.data.code}`,
        icon: "error",
      });
      setOnLoad(false);
    }
  };

  return (
    <>
      <div className="login-page">
        <div className="container d-flex align-items-center position-relative py-5">
          <div className="card shadow-sm w-100 rounded overflow-hidden bg-none">
            <div className="card-body p-0">
              <div className="row gx-0 align-items-stretch">
                {/* Logo & Information Panel*/}
                <div className="col-lg-6">
                  <div className="info d-flex justify-content-center flex-column p-4 h-100 wmnbrandBackGround">
                    <div className="py-5">
                      <h1 className="display-6 fw-bold">Shopper.</h1>
                      <p className="fw-light mb-0">
                        <span
                          className=""
                          style={{ color: "black", fontWeight: "bold" }}
                        >
                          Cửa hàng buôn bán nội thất
                        </span>
                      </p>
                    </div>
                  </div>
                </div>
                {/* Form Panel */}
                <div className="col-lg-6">
                  <div className="d-flex align-items-center px-4 px-lg-5 h-100 wmnbrandBackGroundSecond">
                    <form
                      onSubmit={handleRegister}
                      className="login-form py-5 w-100"
                    >
                      <div className="input-material-group mb-3">
                        <input
                          className="input-material wmn-input"
                          placeholder="Username"
                          id="username"
                          type="text"
                          value={formData.username}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              username: e.target.value,
                            })
                          }
                        />
                        {errors.username && (
                          <div className="text-danger">{errors.username}</div>
                        )}
                      </div>
                      <div className="input-material-group mb-4">
                        <input
                          className="input-material wmn-input"
                          id="email"
                          type="email"
                          placeholder="Email"
                          value={formData.email}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              email: e.target.value,
                            })
                          }
                        />
                        {errors.email && (
                          <div className="text-danger">{errors.email}</div>
                        )}
                      </div>
                      <button
                        className="btn btn-outline-success mb-3"
                        id="login"
                        type="submit"
                        disabled={onload}
                      >
                        {onload ? "Đang đăng ký..." : "Đăng ký"}
                      </button>
                    </form>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="login-footer text-center position-absolute bottom-0 start-0 w-100">
          <p className="text-white">
            Design by{" "}
            <a
              className="external wmnLink colorBoostrap"
              href="https://bootstrapious.com/p/admin-template"
            >
              Bootstrapious
            </a>
            {/* Please do not remove the backlink to us unless you support further theme's development at https://bootstrapious.com/donate. It is part of the license conditions. Thank you for understanding :)*/}
          </p>
        </div>
      </div>
      <link
        rel="stylesheet"
        href="https://use.fontawesome.com/releases/v5.7.1/css/all.css"
        integrity="sha384-fnmOCqbTlWIlj8LyTjo7mOUStjsKC4pOpQbqyi7RrhN7udi9RwhKkMHpvLbHG9Sr"
        crossOrigin="anonymous"
      />
    </>
  );
}

export default Register;
