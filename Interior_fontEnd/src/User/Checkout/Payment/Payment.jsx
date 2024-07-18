import { useContext, useEffect, useState } from "react";
import { CartContext } from "../../../Context/cartContext";
import { processOrderWithVnpay } from "../../../Data/Cart/CartApi";
import Item from "../CartItems/Item/Item";
import UserContext from "../../../Context/userContext";
import { parseJwt } from "../../../Utils/Jwt";
import { selectById } from "../../../Data/User/userApi";
import Swal from "sweetalert2";

function Payment() {
  const [selected, setSelected] = useState(null);
  const [total, setTotal] = useState(0);
  const { cart } = useContext(CartContext);
  const { token } = useContext(UserContext);
  const [user, setUser] = useState({});
  const userId = parseJwt(token).userId;
  useEffect(() => {
    if (cart && cart.length > 0) {
      const sum = cart.reduce(
        (acc, item) => acc + item.productPrice * item.quantity,
        0
      );
      setTotal(sum);
    } else {
      window.location.href = "http://localhost:5173/user";
    }
    selectById(userId).then((res) => {
      setUser(res);
    });
  }, [cart]);

  const handleSubmit = async () => {
    let response;
    let URL = "";
    if (selected) {
      const currentDate = new Date().toISOString().split("T")[0];
      const productIds = [];
      cart.forEach((item) => {
        for (let i = 0; i < item.quantity; i++) {
          productIds.push(item.productId);
        }
      });
      const order = {
        localDate: currentDate,
        status: true,
        username: user.userName,
        productIds: productIds,
      };
      // const savedOrderResponse = await saveCart(order);
      // const savedOrderId = savedOrderResponse.cartId;
      // console.log(savedOrderId);
      response = await processOrderWithVnpay(
        total,
        order.localDate,
        order.status,
        order.username,
        order.productIds
      );
      URL = response.data.url;
      window.location.href = URL;
    } else {
      Swal.fire({
        title: "Lỗi!",
        text: "Vui lòng phương thức thanh toán",
        icon: "error",
      });
    }
  };

  const handleSelect = (option) => {
    setSelected(option);
  };
  return (
    <>
      <article className="carda">
        <div className="container">
          <div className="card-titlea">
            <h2>Thanh toán</h2>
          </div>
          <div className="card-bodya">
            <div className="payment-typea">
              <h4>Chọn phương thức thanh toán dưới đây</h4>
              <div className="typesa flexa justify-space-between">
                {/* <div
                  className={`typea ${selected === "momo" ? "selecteda" : ""}`}
                  onClick={() => handleSelect("momo")}
                >
                  <div className="logoa">
                    <img
                      src="../public/images/MoMo.svg"
                      alt=""
                      style={{ height: "100px" }}
                    />
                  </div>
                  <div className="text">
                    <p>Thanh toán bằng ví điện tử Momo</p>
                  </div>
                </div> */}

                <div
                  className={`typea ${selected === "vnpay" ? "selecteda" : ""}`}
                  onClick={() => handleSelect("vnpay")}
                >
                  <div className="logoa">
                    <img
                      src="../public/images/vnpay.svg"
                      alt=""
                      style={{ height: "100px" }}
                    />
                  </div>
                  <div className="text">
                    <p>Thanh toán bằng ví điện tử VN Pay</p>
                  </div>
                </div>
              </div>
            </div>
            <div className="payment-infoa flexa justify-space-between">
              <div className="columna billing">
                <div className="titlea">
                  <div className="numa">*</div>
                  <h4>Thông tin hóa đơn</h4>
                </div>
                <div className="fielda fulla">
                  {cart &&
                    cart.map((detail) => (
                      <Item details={detail} key={detail.productId} />
                    ))}
                </div>
              </div>
              <div className="columna billing">
                <div className="fielda fulla">
                  <span>Tổng tiền</span>{" "}
                  <span className="ms-auto">{total.toFixed(3)} VNĐ</span>
                </div>
              </div>
            </div>
          </div>
          <div className=" flexa justify-space-between">
            <div className="flex-start">
              <button className="buttona button-secondarya">
                Quay về cửa hàng
              </button>
            </div>
            <div className="flex-end">
              {/* <button className="buttona button-linka">Trở lại mua sắm</button> */}
              <button
                className="buttona button-primarya"
                onClick={() => handleSubmit(selected)}
              >
                Thanh toán
              </button>
            </div>
          </div>
        </div>
      </article>
    </>
  );
}
export default Payment;
