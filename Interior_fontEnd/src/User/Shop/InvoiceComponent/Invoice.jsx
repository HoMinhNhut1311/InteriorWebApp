import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { findCartById } from "../../../Data/Cart/CartApi";

function Invoice() {
  const { orderId } = useParams();
  const [data, setData] = useState({});
  const [groupedProducts, setGroupedProducts] = useState([]);
  const [totalAmount, setTotalAmount] = useState(0);

  useEffect(() => {
    findCartById(orderId).then((cart) => {
      setData(cart);
      const grouped = groupProducts(cart.products);
      setGroupedProducts(grouped.products);
      setTotalAmount(grouped.total);
    });
  }, [orderId]);

  const groupProducts = (products) => {
    const productMap = new Map();
    let total = 0;

    products.forEach((product) => {
      if (productMap.has(product.productId)) {
        const existingProduct = productMap.get(product.productId);
        existingProduct.quantity += 1;
        existingProduct.totalPrice += product.productPrice;
      } else {
        productMap.set(product.productId, {
          ...product,
          quantity: 1,
          totalPrice: product.productPrice,
        });
      }
      total += product.productPrice;
    });

    return {
      products: Array.from(productMap.values()),
      total,
    };
  };

  return (
    <div className="card">
      <div className="card-body">
        <div className="container mb-5 mt-3">
          <div className="container">
            <div className="row">
              <div className="col-xl-4">
                <ul className="list-unstyled">
                  <li className="text-muted">
                    <i className="fas fa-circle" style={{ color: "#84B0CA" }} />{" "}
                    <span className="fw-bold">Mã đơn hàng:</span> #{data.cartId}
                  </li>
                  <li className="text-muted">
                    <i className="fas fa-circle" style={{ color: "#84B0CA" }} />{" "}
                    <span className="fw-bold">Ngày tạo: </span> {data.localDate}
                  </li>
                  <li className="text-muted">
                    <i className="fas fa-circle" style={{ color: "#84B0CA" }} />{" "}
                    <span className="me-1 fw-bold">Trạng thái:</span>
                    {data.status ? (
                      <span className="badge bg-success text-black fw-bold">
                        Đã xử lý
                      </span>
                    ) : (
                      <span className="badge bg-warning text-black fw-bold">
                        Đang xử lý
                      </span>
                    )}
                  </li>
                </ul>
              </div>
            </div>
            <div className="row my-2 mx-1 justify-content-center">
              <table className="table table-striped table-borderless">
                <thead
                  style={{ backgroundColor: "#89B9CD" }}
                  className="text-white"
                >
                  <tr>
                    <th scope="col">STT</th>
                    <th scope="col">Tên sản phẩm</th>
                    <th scope="col">Số lượng</th>
                    <th scope="col">Giá</th>
                    <th scope="col">Tổng</th>
                  </tr>
                </thead>
                <tbody>
                  {groupedProducts.map((p, index) => (
                    <tr
                      style={{ backgroundColor: "#84B0CA" }}
                      className="text-white"
                      key={index}
                    >
                      <th scope="row">{index + 1}</th>
                      <td>{p.productName}</td>
                      <td>{p.quantity}</td>
                      <td>{p.productPrice}</td>
                      <td>{p.totalPrice}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="row">
              <div className="col-xl-8">
                <p className="ms-3"></p>
              </div>
              <div className="col-xl-3">
                <p className="text-black float-start">
                  <span className="text-black me-3">Tổng tiền thanh toán</span>
                  <span style={{ fontSize: 25 }}>${totalAmount.toFixed(2)}</span>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Invoice;
