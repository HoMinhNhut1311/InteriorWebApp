import intance, * as request from "../instanceAxios.js";

export const getPageProduct = async (size, number, categoryId) => {
  const response = await intance.get(
    `product/page?pageSize=${size}&&pageNumber=${number}&&categoryId=${categoryId}`
  );
  return response.data;
};
export const getAllProduct = async(size,number)=>{
  const response = await intance.get(
    `product?page=${number}&&size=${size}`
  );
  return response.data;
}

export const createProduct = async (product) => {
  const response = await intance.post(`product`, product);
  return response;
};

export const updateProduct = async (product, id) => {
  const response = await intance.put(`product/${id}`, product);
  return response;
};

export const findByProductId = async (productId) => {
  const response = await intance.get(`product/${productId}`);
  return response.data;
};
export const deleteProduct = async (id) => {
  const response = await intance.delete(`product/${id}`);
  return response;
};
export const getProductsByProductNameContaining = async (name) => {
  const response = await intance.get(`product/productName/${name}`);
  return response.data;
}

export const uploadFileToProduct = async (file, productId) => {
    const response = await intance.post(`mediaFile/product/${productId}`,file)
    return response.data;
}