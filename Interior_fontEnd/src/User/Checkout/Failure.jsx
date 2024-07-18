function Failure() {
  return (
    <>
      <div className="container">
        <header className="site-header" id="header">
          <h1
            className="site-header__title text-success flex"
            data-lead-id="site-header-title"
          >
            <p className="text-danger">Xin lỗi!</p>
          </h1>
        </header>
        <div className="main-content">
          <h2 className="main-content__body" data-lead-id="main-content-body">
            Đã gặp sự cố khi thanh toán!
          </h2>
        </div>
      </div>
    </>
  );
}

export default Failure;
