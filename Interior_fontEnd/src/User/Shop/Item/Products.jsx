import { Link } from "react-router-dom";
import { useContext, useEffect, useState } from "react";
import UserContext from "../../../Context/userContext";
import { CartContext } from "../../../Context/cartContext";
import Swal from "sweetalert2";

function Products({ product }) {
  const { token } = useContext(UserContext);
  const { cart, addToCart, updateQuantity } = useContext(CartContext);
  const [isLoading, setIsLoading] = useState(true);
  const [totalPrice, setTotalPrice] = useState(0);

  useEffect(() => {
    if (product) {
      setIsLoading(false);
    }
  }, [cart]);
  useEffect(() => {
    calculateTotalPrice();
  }, [cart]);

  const calculateTotalPrice = () => {
    let total = 0;
    cart.forEach((item) => {
      total += item.productPrice * item.quantity;
    });
    setTotalPrice(total);
  };
  const addCart = (e) => {
    e.preventDefault();
    const productPrice = parseFloat(product.productPrice);
    const currentTotal = totalPrice + productPrice;

    if (currentTotal > 1000000000) { // Kiểm tra tổng giá trị không vượt quá 1 tỷ
      Swal.fire({
        title: "Lỗi",
        text: "Tổng tiền trong giỏ hàng đã vượt quá giới hạn. Không thể thêm sản phẩm này!",
        icon: "error",
      });
      return;
    }

    let prod = cart.find((c) => c.productId === product.productId);
    if (prod) {
      updateCart(product, prod.quantity + 1);
    } else {
      saveCart(product);
    }
  };


  const saveCart = (product) => {
    Swal.fire({
      title: "Success",
      text: `Đã thêm sản phẩm vào giỏ hàng`,
      icon: "success",
    }).then(() => {
      addToCart(product, 1);
    });
  };

  const updateCart = (product, quantity) => {
    Swal.fire({
      title: "Success",
      text: `Đã thêm sản phẩm vào giỏ hàng`,
      icon: "success",
    }).then(() => {
      updateQuantity(product, quantity);
    });
  };

  if (isLoading) {
    return (
      <div className="loader">
        <div className="wrapper">
          <div className="circle"></div>
          <div className="line-1"></div>
          <div className="line-2"></div>
          <div className="line-3"></div>
          <div className="line-4"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="col-6 col-md-4">
      <div className="cardd mb-7 ms-7">
        <div className="card-img">
          <Link to={`furniture/${product.productId}`}>
            <a className="card-img-hover" href="product.html">
              <img
                className="card-img-top card-img-back"
                src={product.mediaFilePath}
                alt={product.productName}
              />
              <img
                className="card-img-top card-img-front"
                src={product.mediaFilePath}
                alt={product.productName}
              />
            </a>
          </Link>
          <div className="card-actions">
            <Link to={`furniture/${product.productId}`}>
              <span className="card-action">
                <button
                  className="btn btn-xs btn-circle btn-white-primary"
                  title="view"
                >
                 <i className="bi bi-eye-fill"></i>
                </button>
              </span>
            </Link>
            <span className="card-action">
              {token == null ? (
                <button
                  className="btn btn-xs btn-circle btn-white-primary"
                  title="cart"
                >
                   <i className="bi bi-cart-fill icon-large"></i>
                </button>
              ) : (
                <button
                  className="btn btn-xs btn-circle btn-white-primary"
                  title="cart"
                  onClick={(e) => addCart(e)}
                >
                   <i className="bi bi-cart-fill icon-large"></i>
                </button>
              )}
            </span>
          </div>
        </div>
        <div className="card-body px-0">
          <div className="fs-xs">
            <a className="text-muted" href="shop.html">
              {product.categoryName}
            </a>
          </div>
          <div className="fw-bold">
            <a className="text-body" href="product.html">
              {product.productName}
            </a>
          </div>
          <div className="fw-bold text-muted">{product.productPrice}</div>
        </div>
      </div>
    </div>
  );
}

export default Products;
