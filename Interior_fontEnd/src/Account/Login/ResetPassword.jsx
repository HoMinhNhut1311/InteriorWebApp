import React, { useState } from "react";
import { RingLoader } from "react-spinners";
import { resetPassword } from "../../Data/User/userApi";
import { useNavigate } from "react-router-dom";
import Swal from "sweetalert2";

function ResetPassword() {
    const [onLoad, setOnLoad] = useState(false);
    const [pwNew, setPwNew] = useState('');
    const [pwRepeat, setPwRepeat] = useState('');
    const [error, setError] = useState('');
    const [showPassword, setShowPassword] = useState(false); // State để quản lý hiển thị mật khẩu
    const navi = useNavigate();

    const handleResetPassword = (e) => {
        e.preventDefault();

        if (pwNew !== pwRepeat) {
            setError('Mật khẩu nhập lại không khớp');
            return;
        }

        setError('');
        setOnLoad(true);
        resetPassword(pwNew).then((res) => {
            setOnLoad(false);
            Swal.fire({
                title: "Đổi mật khẩu thành công",
                text: "Chuyển đến trang đăng nhập sau 2s",
                timer: 2000,
                icon : 'success',
                timerProgressBar : 'true'
            }).then(() => navi('/login'));
        });
    };

    const toggleShowPassword = () => {
        setShowPassword(!showPassword);
    };

    return ( 
        <>
            {onLoad && <div className="my-loader-wrapper">
                <div className="my-loader">
                    <RingLoader color="#36d7b7" size={140} loading={onLoad} />
                </div>
            </div>}
            <div className="container pt-5">
                <h2 className="text-danger text-center">Thay đổi mật khẩu</h2>
                <form onSubmit={handleResetPassword}>
                    <div className="form-group mt-4">
                        <label htmlFor="" className="form-label fs-3 fw-bold">Nhập mật khẩu mới</label>
                        <input type={showPassword ? "text" : "password"} className="form-control border border-white text-white" required
                            value={pwNew}
                            onChange={(e) => setPwNew(e.target.value)}
                        />
                    </div>
                    <div className="form-group mt-4">
                        <label htmlFor="" className="form-label fs-3 fw-bold">Nhập lại mật khẩu mới</label>
                        <input type={showPassword ? "text" : "password"} className="form-control border border-white text-white" required
                            value={pwRepeat}
                            onChange={(e) => setPwRepeat(e.target.value)}
                        />
                    </div>
                    {error && <span className="text-danger d-block">{error}</span>}
                    <div className="form-check mt-3">
                        <input className="form-check-input" type="checkbox" id="showPassword" onChange={toggleShowPassword} />
                        <label className="form-check-label" htmlFor="showPassword">
                            Hiển thị mật khẩu
                        </label>
                    </div>
                    <button className="btn btn-success mt-3">Cập nhật mật khẩu</button>
                </form>
            </div>
        </>
    );
}

export default ResetPassword;
