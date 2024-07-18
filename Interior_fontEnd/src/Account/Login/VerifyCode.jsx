import { useContext, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { sendCodeToGmail, verifyCode } from "../../Data/Gmail/GmailApi";
import { RingLoader } from "react-spinners";
import Swal from "sweetalert2";
import UserContext from "../../Context/userContext";

function VerifyCode() {

    const [code, setCode] = useState('')
    const [onLoad, setOnLoad] = useState(false)

    const [countDown, setCountDown] = useState(60);
    const {login} = useContext(UserContext)

    const navi = useNavigate()

    useEffect(() => {
        const timerId = setInterval(() => {
            setCountDown(prev => {
                if (prev === 0) {
                    clearInterval(timerId);
                    return prev;
                }
                return prev - 1;
            });
        },1000)

        return () =>clearInterval(timerId)
        
    },[])

    const param = useParams();

    const handleVerifyCode = (e) => {
        e.preventDefault();
        setOnLoad(true)
        verifyCode(param.email,code).then((res) => {
            setOnLoad(false)
            if (res.data.valid) {
                login(res.data)
                Swal.fire({
                    title : "Mã xác thực chính xác",
                    icon : 'info'
                }).then(() => navi('/resetPassword'))
            }
            else {
                Swal.fire({
                    title : "Mã xác thực không chính xác",
                    icon : 'error'
                })
            }
        })
    }

    const resendCode = () => {
        setCountDown(60)
        setOnLoad(true)
        sendCodeToGmail(param.email).then((res) => {
            setOnLoad(false)
            if (res.status == 200) {
                Swal.fire({
                  title : "Gửi mã thành công",
                  text : "Vui lòng kiểm tra Email "+param.email,
                  icon : 'success'
                })
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
    return ( <>
     {onLoad && <div className="my-loader-wrapper">
                <div className="my-loader">
                    <RingLoader color="#36d7b7" size={140} loading={onLoad} />
                </div>
            </div>}
           <div className="container pt-5">
               <h2 className="text-danger text-center">Xác thực Mã</h2>
               <span>Vui lòng kiểm tra Email của bạn</span>

               <div className="form-group mt-4">
                    <label htmlFor="" className="form-label fs-3 fw-bold">Nhập mã được gửi từ Email</label>
                    <form onSubmit={(e) => handleVerifyCode(e)}>
                    <input type="text" className="form-control border border-white  text-white" required
                        value={code}
                        onChange={(e) => setCode(e.target.value)}
                    />
                    <button className="btn btn-danger mt-3">Gửi mã</button>
                    </form>
               </div>
               <span className="text-warning">Mã của bạn có hiệu lực {countDown}</span>
               <button className="btn btn-outline-light d-block mt-2" onClick={() => resendCode()}>Gửi lại mã</button>
            </div>
    </> );
}

export default VerifyCode;