import intance, * as request from "../instanceAxios.js";

export const saveCart = async (cart) => {
  const response = await intance.post(`cart`, cart);
  return response.data;
};
export const getAllCartByUser = async (userId, number, size) => {
  const response = await intance.get(
    `cart/page?userId=${userId}&pageNumber=${number}&pageSize=${size}`
  );
  return response.data;
};
export const findCartById = async (cartId) => {
  const response = await intance.get(`cart/${cartId}`);
  return response.data;
};
export const processOrderWithVnpay = async (
  amount,
  localDate,
  status,
  username,
  productIds
) => {
  const response = await intance.get(
    `payment/createPayment?amount=${amount}
    &&localDate=${localDate}&status=${status}&username=${username}&productIds=${productIds}`
  );
  return response;
};
