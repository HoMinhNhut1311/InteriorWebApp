import PlaceOrder from "./CartItems/PlaceOrder";

function Checkout() {
  return (
    <div>
      <nav className="py-5">
        <div className="container">
          <div className="row">
            <div className="col-12">
              <ol className="breadcrumb mb-0 fs-xs text-gray-400">
                <li className="breadcrumb-item">
                  <a className="text-gray-400" href="index.html">
                    Trang chủ
                  </a>
                </li>
                <li className="breadcrumb-item">
                  <a className="text-gray-400" href="shopping-cart.html">
                    Giỏ hàng
                  </a>
                </li>
                <li className="breadcrumb-item active">Thanh toán</li>
              </ol>
            </div>
          </div>
        </div>
      </nav>
      <section className="pt-7 pb-12">
        <div className="container">
          <div className="row">
            <div className="col-12 text-center">
              <h3 className="mb-4">Thanh toán</h3>
            </div>
          </div>
          <div className="row">
            {/* <FormCheckout key={1}
              setFee={setFee}
              setDelivery={setDelivery}
              setPayment={setPayment}
            /> */}
            <PlaceOrder key={1} />
          </div>
        </div>
      </section>
    </div>
  );
}
export default Checkout;
