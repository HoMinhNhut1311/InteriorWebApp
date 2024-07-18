import intance, * as request from '../instanceAxios.js'



// Select UserOverView_UserCount (Số lượng mỗi role) -> Response UserOverViewDtoResponse
export const getCountUser = async () => {
    const respone =  await intance.get('role/overview')
    return respone.data;
  }

export const getAllRole = async () => {
  const response = await intance.get('role');
  return response.data;
}

