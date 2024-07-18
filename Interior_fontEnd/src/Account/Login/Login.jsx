import { useContext, useState } from "react";
import Swal from "sweetalert2";
import { Link, useNavigate } from "react-router-dom";
import "/public/css/style.default.css"
import "/public/css/custom.css";
import { loginApi } from "../../Data/User/userApi";
import UserContext from "../../Context/userContext";
import { RingLoader } from "react-spinners";
import LoginWithGoogle from "./LoginWithGoogle";
function Login() {
  const [formData, setFormData] = useState({
    username: "admin",
    password: "1",
  });

  const [onload, setOnLoad] = useState(false);

  const { login } = useContext(UserContext);

  const navigate = useNavigate();

  const handleNavigate = (roles) => {
    return roles.includes("ADMIN") ? navigate("/admin") : navigate("/user");
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    // Gọi Api Login
    setOnLoad(true);
    const respone = await loginApi(formData.username, formData.password);
    if (respone.status === 200) {
      console.log(respone.data);
      login(respone.data);
      setOnLoad(false);
      Swal.fire({
        title: "Đăng nhập thành công",
        text: `${respone.data.fullName ? 'Chào bạn: '+respone.data.fullName : 'Ok'}`,
        icon: "success",
      })
        .then(() => {
          handleNavigate(respone.data.roleNames);
        })
        .finally(() => {
          setOnLoad(false);
        });
    } else {
      Swal.fire({
        title: respone.data.message,
        text: `Mã lỗi : ${respone.data.code}`,
        icon: "error",
      });
      setOnLoad(false);
    }
  };

  return (
    <>
      {onload && (
        <div className="my-loader-wrapper">
          <div className="my-loader">
            <RingLoader color="#36d7b7" size={200} />
          </div>
        </div>
      )}
      <div className="login-page">
        <div className="container d-flex align-items-center position-relative py-5">
          <div className="card shadow-sm w-100 rounded overflow-hidden bg-none">
            <div className="card-body p-0">
              <div className="row gx-0 align-items-stretch">
                {/* Logo & Information Panel*/}
                <div className="col-lg-6 ">
                  <div className="info d-flex justify-content-center flex-column p-4 h-100 wmnbrandBackGround">
                    <div className="py-5">
                      <h1 className="display-6 fw-bold">Hello World</h1>
                      <p className="fw-light mb-0">
                        <span
                          className=""
                          style={{ color: "black", fontWeight: "bold" }}
                        >
                          WMN - (TemplateBy : Bootstrapious.com)
                        </span>
                      </p>
                    </div>
                  </div>
                </div>
                {/* Form Panel    */}
                <div className="col-lg-6">
                  <div className="d-flex align-items-center px-4 px-lg-5 h-100 wmnbrandBackGroundSecond">
                    <form
                      onSubmit={handleLogin}
                      className="login-form py-5 w-100"
                      method="get"
                      action="index.html"
                    >
                      <div className="input-material-group mb-3">
                        <input
                          className="input-material wmn-input"
                          placeholder="Username"
                          id="login-username"
                          type="text"
                          name="loginUsername"
                          autoComplete="off"
                          required=""
                          data-validate-field="loginUsername"
                          value={formData.username}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              username: e.target.value,
                            })
                          }
                        />
                      </div>
                      <div className="input-material-group mb-4">
                        <input
                          className="input-material wmn-input"
                          id="login-password"
                          type="password"
                          name="loginPassword"
                          required=""
                          data-validate-field="loginPassword"
                          placeholder="Password"
                          value={formData.password}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              password: e.target.value,
                            })
                          }
                        />
                      </div>
                      <button
                        className="btn btn-outline-success mb-3"
                        id="login"
                        type="submit"
                      >
                        Login
                      </button>
                      <LoginWithGoogle/>
                      <br />
                      <Link className="text-sm text-paleBlue wmnLink" to="/forgotPassword">
                        Forgot Password?
                      </Link>
                      <br />
                      <small className="text-gray-500">
                        Do not have an account?{" "}
                      </small>
                      <Link className="text-sm text-paleBlue wmnLink" to="/register">
                      Signup
                     </Link>
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

export default Login;
