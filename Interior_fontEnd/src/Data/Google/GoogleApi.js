import instance from "../instanceAxios";

export const getAuthUrl = async () => {
    const response = await instance.get('auth/google/url');
    return response.data;
}

export const callBackUrlGoogle = async (code) => {
    console.log("call");
    const response = await instance.get(`auth/google/callback?code=${code}`)
    return response.data;
}

