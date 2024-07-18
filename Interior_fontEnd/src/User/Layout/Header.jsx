import { Fragment, useContext, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Offcanvas } from "react-bootstrap";
import { CartContext } from "../../Context/cartContext";
import UserContext from "../../Context/userContext";
import ShoppingCart from "./Cart/ShoppingCart";
import Swal from "sweetalert2";

const buttonStyle = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  height: "50px",
};
function Header() {
  const [showCart, setShowCart] = useState(false);
  const [showSearch, setShowSearch] = useState(false);
  const { token, setToken } = useContext(UserContext);
  const { cart, setCart } = useContext(CartContext);
  const [total, setTotal] = useState(0);
  const navi = useNavigate();
  const handleShowCart = () => setShowCart(true);
  const handleCloseCart = () => setShowCart(false);
  const handleShowSearch = () => setShowSearch(true);
  const handleCloseSearch = () => setShowSearch(false);
  useEffect(() => {
    if (cart || total < 1e9) {
      const sum = cart.reduce(
        (acc, item) => acc + item.productPrice * item.quantity,
        0
      );
      setTotal(sum.toLocaleString());
    }
  }, [cart]);
  const logout = async () => {
    await Swal.fire({
      title: "Đăng xuất thành công",
      text: `Tự động chuyển sang trang Đăng Nhập sau 2 giây nữa`,
      timer: 2000,
      timerProgressBar: true,
      background: "#36d7b7",
      color: "white",
      icon: "info",
    }).then(() => {
      setCart([]);
      navi("/login");
    });
    sessionStorage.removeItem("token");
    setToken(null);
  };
  return (
    <div>
      <Fragment>
        <nav className="navbar navbar-expand-lg navbar-light bg-white border border-bottom-2">
          <div className="container">
            <Link to={"/user"}>
              <a className="navbar-brand"> Shopper. </a>
            </Link>

            <button
              className="navbar-toggler"
              type="button"
              data-bs-target="#navbarCollapse"
              aria-controls="navbarCollapse"
              aria-expanded="false"
              aria-label="Toggle navigation"
            >
              <span className="navbar-toggler-icon"></span>
            </button>

            <div className="collapse navbar-collapse" id="navbarCollapse">
              <ul className="navbar-nav mx-auto">
                <li className="nav-item dropdown">
                  <Link to={"/user"}>
                    <a className="nav-link">Trang chủ</a>
                  </Link>
                </li>
                <li className="nav-item dropdown">
                  <Link to={`/user/shop`} className="nav-link">
                    Cửa hàng
                  </Link>
                </li>
                <li className="nav-item dropdown">
                  <Link to={`/user/about`} className="nav-link">
                    Về chúng tôi
                  </Link>
                </li>
                <li className="nav-item">
                  <Link to={`/user/blog`} className="nav-link">
                    Tài liệu
                  </Link>
                </li>
              </ul>

              <ul className="navbar-nav flex-row">
                {/* <li className="nav-item">
                  <a
                    className="nav-link"
                    href="#modalSearch"
                    onClick={handleShowSearch}
                  >
                    <i className="bi bi-search icon-large"></i>
                  </a>
                </li> */}
                <li className="nav-item ms-lg-n4">
                  {token ? (
                    <div className="top-account">
                      <Link to={`/user/detail`}>
                        <a className="nav-link">
                          <i className="bi bi-person-fill icon-large"></i>
                        </a>
                      </Link>
                      <div
                        className="top-dropdown border border-2"
                        style={{
                          padding: "5px 10px 15px 10px",
                          marginTop: "-110px",
                          width: "16%",
                        }}
                      >
                        <div>
                          <button
                            style={{ marginTop: "5px" }}
                            type="button"
                            className="button-facebook"
                          >
                            <Link to={`/user/detail`} className="text-light">
                              <span>Thông tin cá nhân</span>
                            </Link>
                          </button>
                          <button
                            style={{ marginTop: "5px" }}
                            type="button"
                            className="button-facebook"
                          >
                            <Link
                              to={`/user/detail/change-password`}
                              className="text-light"
                            >
                              <span>Đổi mật khẩu</span>
                            </Link>
                          </button>
                          <button
                            style={{ marginTop: "5px" }}
                            type="button"
                            className="button-facebook center_center"
                            onClick={logout}
                          >
                            <span className="icon_facebook"></span>
                            <span className="text-light">Đăng xuất</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <Link to={"./login"}>
                      <a className="nav-link">
                        <i className="bi bi-person-fill icon-large"></i>
                      </a>
                    </Link>
                  )}
                </li>
                <li className="nav-item ms-lg-n4">
                  {token ? (
                    <Link to={"/user/detail/orderPage"}>
                      <a className="nav-link">
                        <i className="bi bi-receipt icon-large"></i>
                      </a>{" "}
                    </Link>
                  ) : (
                    <Link to={"./login"}>
                      {" "}
                      <a className="nav-link">
                        <i className="bi bi-receipt icon-large"></i>
                      </a>
                    </Link>
                  )}
                </li>
                <li className="nav-item ms-lg-n4">
                  <a
                    className="nav-link"
                    href="#modalShoppingCart"
                    onClick={handleShowCart}
                  >
                    <span data-cart-items={cart.length}>
                      <i className="bi bi-cart-fill icon-large"></i>
                    </span>
                  </a>
                </li>
              </ul>
              <Offcanvas
                show={showCart}
                onHide={handleCloseCart}
                placement="end"
                style={{ width: "500px" }}
              >
                <Offcanvas.Header closeButton>
                  <Offcanvas.Title>
                    {token ? (
                      <div> Giỏ hàng của bạn ({cart.length})</div>
                    ) : (
                      <div>Vui lòng đăng nhập trước</div>
                    )}
                  </Offcanvas.Title>
                </Offcanvas.Header>
                <Offcanvas.Body>
                  <ul className="list-group list-group-lg list-group-flush">
                    {cart &&
                      cart.map((item) => (
                        <ShoppingCart key={item.productId} detailCarts={item} />
                      ))}
                  </ul>
                </Offcanvas.Body>
                {cart.length > 0 && (
                  <div className="offcanvas-footer justify-between lh-fixed fs-sm bg-light mt-auto w-100">
                    <strong>Tổng tiền</strong>
                    <strong className="ms-auto">${total}</strong>
                  </div>
                )}
                <div className="offcanvas-body">
                  {cart.length > 0 && cart && (
                    <>
                      <Link
                        className="btn w-100 btn-dark"
                        to="checkout"
                        style={buttonStyle}
                      >
                        <span className="">Thanh toán</span>
                      </Link>
                      {/* <Link
                        to="cart"
                        className="btn w-100 btn-outline-dark"
                        style={buttonStyle}
                      >
                        <span className="">Xem giỏ hàng</span>
                      </Link> */}
                    </>
                  )}
                </div>
              </Offcanvas>
              <Offcanvas
                show={showSearch}
                onHide={handleCloseSearch}
                placement="end"
              >
                <Offcanvas.Header closeButton>
                  <Offcanvas.Title>
                    <div className="offcanvas-header lh-fixed fs-lg">
                      <strong className="mx-auto">Tìm sản phẩm</strong>
                    </div>
                  </Offcanvas.Title>
                </Offcanvas.Header>
                <Offcanvas.Body>{/* <SearchProd /> */}</Offcanvas.Body>
              </Offcanvas>
            </div>
          </div>
        </nav>
      </Fragment>
    </div>
  );
}

export default Header;
