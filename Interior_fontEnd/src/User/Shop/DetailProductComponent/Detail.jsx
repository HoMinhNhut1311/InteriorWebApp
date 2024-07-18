import { useContext, useState } from "react";
import { CartContext } from "../../../Context/cartContext";
import Swal from "sweetalert2";

function Detail({ product }) {
  const [stock, setStock] = useState(1);
  const { cart, addToCart, updateQuantity } = useContext(CartContext);
  const decrease = () => {
    if (stock !== 1) setStock(stock - 1);
  };
  const increase = () => {
    if (stock >= 1) setStock(stock + 1);
  };

  const addCart = (e) => {
    e.preventDefault();
    let prod = cart.find((c) => c.productId === product.productId);
    if (prod) {
      updateCart(prod, prod.quantity + stock);
    } else {
      saveCart(product, stock);
    }
  };

  const saveCart = (p, s) => {
    Swal.fire({
      title: "Success",
      text: `Đã thêm sản phẩm vào giỏ hàng`,
      icon: "success",
    }).then(() => {
      addToCart(p, s);
    });
  };
  const updateCart = (p, q) => {
    Swal.fire({
      title: "Success",
      text: `Đã thêm sản phẩm vào giỏ hàng`,
      icon: "success",
    }).then(() => {
      updateQuantity(p, q);
    });
  };
  return (
    <section>
      <div className="container">
        <div className="row">
          <div className="col-12">
            <div className="row">
              <div className="col-12 col-md-6">
                <div className="card">
                  <div className="badge bg-primary card-badge text-uppercase">
                    Sale
                  </div>

                  <div
                    className="mb-2 flickity-enabled is-fade"
                    data-flickity='{"draggable": false, "fade": true}'
                    id="productSlider"
                    tabIndex={0}
                  >
                    <div
                      className="flickity-viewport"
                      style={{ height: "300.963px" }}
                    >
                      <div
                        className="flickity-slider"
                        style={{ transform: "translateX(0%)" }}
                      >
                        <a
                          href="#"
                          data-bigpicture={{ imgSrc: product.mediaFilePath }}
                          className="flickity-cell is-selected"
                          style={{ transform: "translateX(0%)", opacity: "1" }}
                        >
                          <img
                            src={product.mediaFilePath}
                            alt={product.productName}
                            className="card-img-top"
                          />
                        </a>
                        <a
                          href="#"
                          data-bigpicture={{ imgSrc: product.mediaFilePath }}
                          className="flickity-cell"
                          aria-hidden="true"
                          style={{ transform: "translateX(0%)", opacity: "0" }}
                        >
                          <img
                            src={"../" + product.mediaFilePath}
                            alt="..."
                            className="card-img-top"
                          />
                        </a>
                        <a
                          href="#"
                          data-bigpicture={{ imgSrc: product.mediaFilePath }}
                          className="flickity-cell"
                          aria-hidden="true"
                          style={{ transform: "translateX(0%)", opacity: "0" }}
                        >
                          <img
                            src={product.mediaFilePath}
                            alt="..."
                            className="card-img-top"
                          />
                        </a>
                      </div>
                    </div>
                  </div>
                </div>

                <div
                  className="flickity-nav mx-n2 mb-10 mb-md-0 flickity-enabled is-draggable"
                  data-flickity='{"asNavFor": "#productSlider", "contain": true, "wrapAround": false}'
                  tabIndex={0}
                >
                  <div className="flickity-viewport" style={{ height: "97px" }}>
                    <div
                      className="flickity-slider"
                      style={{ transform: "translateX(0%)" }}
                    >
                      <div
                        className="col-12 px-2 flickity-cell is-selected is-nav-selected"
                        style={{
                          maxWidth: "113px",
                          transform: "translateX(0%)",
                        }}
                      >
                        <div
                          className="ratio ratio-1x1 bg-cover"
                          style={
                            {
                              // backgroundImage: `url(${product.images[0].url})`,
                            }
                          }
                        ></div>
                      </div>
                      <div
                        className="col-12 px-2 flickity-cell"
                        style={{
                          maxWidth: "113px",
                          transform: "translateX(100%)",
                        }}
                        aria-hidden="true"
                      >
                        {/* <!-- Image --> */}
                        <div
                          className="ratio ratio-1x1 bg-cover"
                          style={
                            {
                              // backgroundImage: `url(${product.images[0].url})`,
                            }
                          }
                        ></div>
                      </div>
                      <div
                        className="col-12 px-2 flickity-cell"
                        style={{
                          maxWidth: "113px",
                          transform: "translateX(200%)",
                        }}
                        aria-hidden="true"
                      >
                        {/* <!-- Image --> */}
                        <div
                          className="ratio ratio-1x1 bg-cover"
                          style={
                            {
                              // backgroundImage: `url(${product.images[1].url})`,
                            }
                          }
                        ></div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="col-12 col-md-6 ps-lg-10">
                <h3 className="mb-2">{product.productName}</h3>

                {/* <!-- Price --> */}
                <div className="mb-7">
                  <span className="fs-lg fw-bold text-gray-350 text-decoration-line-through">
                    ${Number(product.productPrice) + 100}
                  </span>
                  <span className="ms-1 fs-5 fw-bolder text-primary">
                    ${product.productPrice}
                  </span>
                </div>
                <div className="row gx-5 float-s mb-5">
                  <div className="d-flex align-items-center">
                    <b className="fs-6 me-2">Kích thước</b>{" "}
                    <span className="border border-1 ps-2 pe-2">
                      D800 - R800 - C670 mm
                    </span>{" "}
                  </div>
                </div>
                <div className="row gx-5 float-s">
                  <div className="d-flex align-items-center">
                    <p>Mã: {product.productId}</p>
                  </div>
                </div>
                <div className="row gx-5 float-s">
                  <div className="d-flex align-items-center">
                    <p>Danh mục: {product.categoryName}</p>
                  </div>
                </div>
                {/* <!-- Form --> */}
                <form>
                  <div className="row gx-5 mb-7">
                    <div className="col-12 col-lg">
                      <div className="quantity">
                        <button
                          className="minus-btn"
                          type="button"
                          name="button"
                          onClick={decrease}
                        >
                          -
                        </button>
                        <input
                          type="text"
                          name="quantity"
                          value={stock}
                          min={1}
                          title="plus"
                          style={{ width: "150px" }}
                        />
                        <button
                          className="plus-btn"
                          type="button"
                          name="button"
                          onClick={increase}
                        >
                          +
                        </button>
                      </div>
                    </div>
                    <div className="col-12 col-lg">
                      <button
                        type="submit"
                        className="btn w-100 btn-dark mb-2"
                        onClick={addCart}
                        title="submit"
                      >
                        Thêm vào giỏ hàng{" "}
                        <i className="fe fe-shopping-cart ms-2"></i>
                      </button>
                    </div>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
export default Detail;
