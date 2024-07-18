import intance, * as request from "../instanceAxios.js";

export const getProductSoldByLocalDate = async(localDate) =>{
    const response = await intance.get(`cartProduct/statistical?localDate=${localDate}`)
    console.log(response);
    return response.data;
}

export const getProductBestSeller = async() =>{
    const response = await intance.get(`product/bestSeller`)
    console.log(response);
    return response.data;
}