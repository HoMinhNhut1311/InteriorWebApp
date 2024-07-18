import { useContext, useEffect, useState } from "react";
import { CartContext } from "../../../Context/cartContext";
import Item from "./Item/Item";
import { saveCart } from "../../../Data/Cart/CartApi";
import Swal from "sweetalert2";
import UserContext from "../../../Context/userContext";
import { parseJwt } from "../../../Utils/Jwt";
import { selectById } from "../../../Data/User/userApi";
import { useNavigate } from "react-router-dom";

function PlaceOrder() {
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const { cart, removeFromCart } = useContext(CartContext);
  const { token } = useContext(UserContext);
  const [user, setUser] = useState({});
  const userId = parseJwt(token).userId;
  const navi = useNavigate("");
  useEffect(() => {
    if (cart && cart.length > 0) {
      const sum = cart.reduce(
        (acc, item) => acc + item.productPrice * item.quantity,
        0
      );
      setTotal(sum);
    } else {
      setTotal(0);
    }
    selectById(userId).then((res) => {
      setUser(res);
    });
  }, [cart]);

  const handlePlaceOrder = () => {
    setIsLoading(true);
    const currentDate = new Date().toISOString().split("T")[0];
    const productIds = [];

    cart.forEach((item) => {
      for (let i = 0; i < item.quantity; i++) {
        productIds.push(item.productId);
      }
    });
    setTimeout(() => {
      setIsLoading(false);
      const order = {
        localDate: currentDate,
        status: false,
        username: user.userName,
        productIds: productIds,
      };
      Swal.fire({
        title: "Đã thanh toán thành công",
        icon: "success",
        text: `Tự động chuyển sang trang chủ sau 3 giây nữa`,
        timer: 3090,
        timerProgressBar: true,
      }).then(() => {
        saveCart(order);
        cart.forEach((item) => {
          for (let i = 0; i < item.quantity; i++) {
            removeFromCart(item.productId);
          }
        });
        navi("/user");
      });
    }, 2000);
  };

  if (isLoading) {
    return (
      <div
        className="d-flex justify-content-center align-items-center"
        style={{ height: "100vh" }}
      >
        <svg viewBox="0 0 240 240" height="240" width="240" className="pl">
          <circle
            strokeLinecap="round"
            strokeDashoffset="-330"
            strokeDasharray="0 660"
            strokeWidth="20"
            stroke="#000"
            fill="none"
            r="105"
            cy="120"
            cx="120"
            className="pl__ring pl__ring--a"
          ></circle>
          <circle
            strokeLinecap="round"
            strokeDashoffset="-110"
            strokeDasharray="0 220"
            strokeWidth="20"
            stroke="#000"
            fill="none"
            r="35"
            cy="120"
            cx="120"
            className="pl__ring pl__ring--b"
          ></circle>
          <circle
            strokeLinecap="round"
            strokeDasharray="0 440"
            strokeWidth="20"
            stroke="#000"
            fill="none"
            r="70"
            cy="120"
            cx="85"
            className="pl__ring pl__ring--c"
          ></circle>
          <circle
            strokeLinecap="round"
            strokeDasharray="0 440"
            strokeWidth="20"
            stroke="#000"
            fill="none"
            r="70"
            cy="120"
            cx="155"
            className="pl__ring pl__ring--d"
          ></circle>
        </svg>
      </div>
    );
  }

  return (
    <div className="col-12 col-md-6 col-lg-4 offset-lg-1">
      <h6 className="mb-7">Đơn hàng ({cart.length})</h6>
      <hr className="my-7" />
      <ul className="list-group list-group-lg list-group-flush-y list-group-flush-x mb-7">
        {cart &&
          cart.map((detail) => (
            <Item details={detail} key={detail.productId} />
          ))}
      </ul>
      <div className="card mb-9 bg-light">
        <div className="card-body">
          <ul className="list-group list-group-sm list-group-flush-y list-group-flush-x">
            <li className="list-group-item d-flex fs-lg fw-bold">
              <span>Tổng tiền</span>{" "}
              <span className="ms-auto">${total.toFixed(2)}</span>
            </li>
          </ul>
        </div>
      </div>
      <button className="btn w-100 btn-dark" onClick={handlePlaceOrder}>
        Đặt hàng
      </button>
    </div>
  );
}

export default PlaceOrder;
