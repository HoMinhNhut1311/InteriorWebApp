import { error } from "jquery";
import instance from "../instanceAxios";

export const sendCodeToGmail = async (email) => {
    try {
        const response = await instance.get(`email/sendGmail/forgotPassword/${email}`);
        return {
            status: response.status,
            message: response.data
        };
    } catch (error) {
        console.log(error.response?.data?.message);
        return {
            status: error.response?.status || 500,
            message: error.response?.data?.message || "Internal Server Error"
        };
    }
};


export const verifyCode = async (email , randomCode) => {
    const response = await instance.post('email/verifyCode', {
        email : email,
        randomCode : randomCode
    })
    return response;
}

