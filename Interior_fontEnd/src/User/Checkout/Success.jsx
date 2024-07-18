import { Link } from "react-router-dom";

function Success() {
  return (
    <>
      <div className="container mt-5">
        <header className="site-header" id="header">
          <h1
            className="site-header__title text-success flex d-flex justify-content-center"
            data-lead-id="site-header-title"
          >
            CẢM ƠN!
          </h1>
        </header>
        <div className="main-content">
          <h2 className="main-content__body" data-lead-id="main-content-body">
            Xin chân thành cảm ơn bạn đã tin tưởng và mua hàng chúng tôi!
          </h2>
        </div>
        <div className="d-flex justify-content-center ">
          <Link to={"/user"}>
            <button className="buttona button-secondarya text-dark">
              Quay về cửa hàng
            </button>
          </Link>
        </div>
      </div>
    </>
  );
}
export default Success;
