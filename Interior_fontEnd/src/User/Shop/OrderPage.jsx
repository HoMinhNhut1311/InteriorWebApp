import { useContext, useEffect, useState } from "react";
import { getAllCartByUser } from "../../Data/Cart/CartApi";
import UserContext from "../../Context/userContext";
import { parseJwt } from "../../Utils/Jwt";
import DetailOrder from "./DetailOrderComponent/DetailOrder";
const PAGE_SIZE = 5;
function OrderPage() {
  const [orders, setOrder] = useState([]);
  const [pagePresent, setPagePresent] = useState(0);
  const [pageSize, setPageSize] = useState();
  const [onLoad, setOnLoad] = useState(false);
  const { token } = useContext(UserContext);
  const userId = parseJwt(token).userId;

  const setDataPage = async (id, number, size) => {
    setOnLoad(true);
    const response = await getAllCartByUser(id, number, size);
    setOrder(response.content);
    setPageSize(response.totalPages);
    setOnLoad(false);
  };
  const refresh = async () => {
    console.log("Cập nhật lại trang");
    setOnLoad(true);
    setDataPage(userId, pagePresent, PAGE_SIZE);
  };
  useEffect(() => {
    refresh();
  }, []);


  useEffect(() => {
    setDataPage(userId, pagePresent, PAGE_SIZE);
    console.log("Cập nhật Data Page");
  }, [pagePresent]);


  const handleNext = () => {
    pagePresent === pageSize - 1
      ? setPagePresent(0)
      : setPagePresent((pres) => pres + 1);
  };

  // Hàm Prev
  const handlePrev = () => {
    pagePresent === 0
      ? setPagePresent(pageSize - 1)
      : setPagePresent((pres) => pres - 1);
  };
  return (
    <>
      <div className="formbold-main-wrapper">
        <div className="formbold-form-container d-flex border border-2">
          <table>
            <thead>
              <tr>
                <th>STT</th>
                <th>Mã đơn hàng</th>
                <th>Ngày đặt hàng</th>
                <th>Tổng tiền</th>
                <th>Trạng thái</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {orders.map((order, index) => (
                <DetailOrder index={index} order={order} key={index} />
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="col-12 d-flex justify-content-end mb-2">
        <button className="btn btn-danger" onClick={() => handlePrev()}>
          Trước đó
        </button>
        <div className="numberPage mx-4 text-center m-2 fw-bold fs-5">
          <span className="pagePresent">{pagePresent + 1}</span>/
          <span className="pageSize">{pageSize}</span>
        </div>
        <button className="btn btn-success" onClick={() => handleNext()}>
          Tiếp theo
        </button>
      </div>
    </>
  );
}
export default OrderPage;
