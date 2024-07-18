import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

function DetailOrder({ order, index }) {
  const [total, setTotal] = useState(0);
  useEffect(() => {
    let sum = order.products.reduce(
      (acc, item) => acc + item.productPrice,
      0
    );
    setTotal(sum);
  });
  return (
    <tr key={index} style={{height:"80px"}}>
      <td>{index+1}</td>
      <td>{order.cartId}</td>
      <td>{order.localDate}</td>
      <td>{total}</td>
      <td>{order.status ? "Đã xử lý" : "Đang chờ xử lý"}</td>
      <td>
        <Link to={`${order.cartId}`}>
        <button className="btn btn-info" style={{borderRadius:"30px"}}>Xem chi tiết</button>
        </Link>
      </td>
    </tr>
  );
}
export default DetailOrder;
