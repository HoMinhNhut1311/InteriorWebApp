import React, { useContext, useEffect, useState } from "react";
import { getAuthUrl,callBackUrlGoogle } from "../../Data/Google/GoogleApi";
import { Link, useNavigate } from "react-router-dom";
import Swal from "sweetalert2";
import UserContext from "../../Context/userContext";

function LoginWithGoogle(   ) {
    const [authUrl, setAuthUrl] = useState('');

   const queryParam = new URLSearchParams(window.location.search)
   const navi = useNavigate();
   const { login } = useContext(UserContext);

    useEffect(() => {
        getAuthUrl().then((res) => {
           setAuthUrl(res);
        });
    }, []);


    const handleLoginWithGoogle = async (code) => {
        console.log(code);
        const res = await callBackUrlGoogle(code);
        console.log(res);
        login(res)
        if (res.firstOauth2) {
            Swal.fire({
                title : "Chào mừng bạn lần đầu tham gia với chúng tôi với Google Account",
                icon : 'success'
            }).then(() => {
                navi('/user')
            })
        }
        else {
        Swal.fire({
            title : "Đăng nhập Google thành công",
            text : `Chào bạn ${res.fullName}`,
            icon : 'success'
        }).then(() => {
            navi('/user')
        })
        queryParam.set('code',null)
    }
    }

    useEffect(() => {
        const code  = queryParam.get('code');
       if (code) {
            handleLoginWithGoogle(code);
       }
    },[queryParam])

    return (
        <>
            <Link to={authUrl} className="btn btn-outline-light ms-2 mb-3">
            Đăng nhập với Google
        </Link>
        </>

    );
}

export default LoginWithGoogle;
    