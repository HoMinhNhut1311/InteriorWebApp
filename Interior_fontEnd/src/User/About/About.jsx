function About() {
  return (
    <div className="why-choose-section">
      <div className="container">
        <div className="row justify-content-between align-items-center">
          <div className="col-lg-6">
            <h2 className="section-title">Tại Sao Chọn Chúng Tôi</h2>
            <p>
              Chúng tôi cam kết mang đến cho khách hàng những trải nghiệm mua sắm tốt nhất. Với đội ngũ chuyên nghiệp và dịch vụ tận tâm, chúng tôi luôn sẵn sàng hỗ trợ bạn mọi lúc, mọi nơi.
            </p>
            <div className="row my-5">
              <div className="col-6 col-md-6">
                <div className="feature">
                  <div className="icon">
                    <img
                      src="/public/images/truck.svg"
                      alt="Hình Ảnh"
                      className="img-fluid"
                    />
                  </div>
                  <h3>Giao Hàng Nhanh & Miễn Phí</h3>
                  <p>
                    Chúng tôi cung cấp dịch vụ giao hàng nhanh chóng và miễn phí cho tất cả các đơn hàng. Đảm bảo bạn nhận được sản phẩm một cách nhanh nhất.
                  </p>
                </div>
              </div>
              <div className="col-6 col-md-6">
                <div className="feature">
                  <div className="icon">
                    <img
                      src="/public/images/bag.svg"
                      alt="Hình Ảnh"
                      className="img-fluid"
                    />
                  </div>
                  <h3>Dễ Dàng Mua Sắm</h3>
                  <p>
                    Trang web của chúng tôi được thiết kế thân thiện với người dùng, giúp bạn dễ dàng tìm kiếm và mua sắm sản phẩm chỉ với vài cú click chuột.
                  </p>
                </div>
              </div>
              <div className="col-6 col-md-6">
                <div className="feature">
                  <div className="icon">
                    <img
                      src="/public/images/support.svg"
                      alt="Hình Ảnh"
                      className="img-fluid"
                    />
                  </div>
                  <h3>Hỗ Trợ 24/7</h3>
                  <p>
                    Đội ngũ hỗ trợ khách hàng của chúng tôi luôn sẵn sàng giải đáp mọi thắc mắc của bạn bất kể ngày hay đêm.
                  </p>
                </div>
              </div>
              <div className="col-6 col-md-6">
                <div className="feature">
                  <div className="icon">
                    <img
                      src="/public/images/return.svg"
                      alt="Hình Ảnh"
                      className="img-fluid"
                    />
                  </div>
                  <h3>Hoàn Trả Dễ Dàng</h3>
                  <p>
                    Chính sách hoàn trả đơn giản và thuận tiện của chúng tôi giúp bạn yên tâm hơn khi mua sắm.
                  </p>
                </div>
              </div>
            </div>
          </div>
          <div className="col-lg-5">
            <div className="img-wrap">
              <img
                src='/public/images/sofa.png'
                alt="Hình Ảnh"
                className="img-fluid"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default About;
