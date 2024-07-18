import { useState } from "react";
import { sendCodeToGmail } from "../../Data/Gmail/GmailApi";
import Swal from "sweetalert2";
import { useNavigate } from "react-router-dom";
import { RingLoader } from "react-spinners";


function ForgotPassword() {

    const [email, setEmail] = useState('hnhut1200@gmail.com')
    const navi = useNavigate()
    const [onLoad, setOnLoad] = useState(false)

    const handleGetCodeToEmail = (e) => {
        e.preventDefault();
        setOnLoad(true)
        sendCodeToGmail(email).then((res) => {
            setOnLoad(false)
             if (res.status == 200) {
                  Swal.fire({
                    title : "Gửi mã thành công",
                    text : "Vui lòng kiểm tra Email "+email,
                    icon : 'success'
                  }).then(() => navi(`/verifyCode/${email}`))
             }
             else {
                Swal.fire({
                    title : "Yêu cầu thất bại",
                    text : res.message,
                    icon : 'error'
                })
             }
        })
    }

    return ( 
        <>
       {onLoad && <div className="my-loader-wrapper">
                <div className="my-loader">
                    <RingLoader color="#36d7b7" size={140} loading={onLoad} />
                </div>
            </div>}
            <div className="container pt-5">
               <h2 className="text-danger text-center">Quên mật khẩu</h2>

               <div className="form-group mt-4">
                    <label htmlFor="" className="form-label fs-3 fw-bold">Nhập Email của bạn</label>
                    <form onSubmit={(e) => handleGetCodeToEmail(e)}>
                    <input type="email" className="form-control border border-white  text-white" required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                    />
                    <button className="btn btn-danger mt-3">Gửi mã</button>
                    </form>
               </div>
            </div>
        </>
     );
}

export default ForgotPassword;