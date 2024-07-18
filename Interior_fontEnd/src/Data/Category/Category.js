import instance from "../instanceAxios";

export const getAllCategory = async () => {
    const response = await instance.get('category')
    return response.data;
}