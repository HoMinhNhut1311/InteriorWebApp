// import React, { useState } from "react";
// import Product from "../../../../models/Product";
// import { searchProduct } from "../../../../api/ProductAPI";
// import { Link } from "react-router-dom";
// function SearchProd() {
//   const [category, setCategory] = useState("");
//   const [keySearch, setKeySearch] = useState("");
//   const [temp, setTemp] = useState("");
//   const [listProduct, setListProduct] = useState([]);
//   const search = (e) => {
//     e.preventDefault();
//     // searchProduct(keySearch).then(product=>
//     //     setListProduct(product)
//     // )
//   };
//   return (
//     <>
//       <div className="offcanvas-body">
//         <form>
//           <div className="input-group input-group-merge">
//             <input
//               className="form-control"
//               type="search"
//               placeholder="Search"
//               onChange={(e) => {
//                 setTemp(e.target.value);
//                 setKeySearch(temp);
//               }}
//               value={temp}
//             />
//             <div className="input-group-append">
//               <button
//                 className="btn btn-outline-border"
//                 type="submit"
//                 title="search"
//                 onClick={(e)=>{
//                     search(e)
//                 }}
//               >
//                 <i className="fe fe-search"></i>
//               </button>
//             </div>
//           </div>
//         </form>
//       </div>
//       <div className="offcanvas-body border-top fs-sm">
//         <p>Kết quả tìm kiếm:</p>

//         {listProduct.map((prod) => (
//                       <div
//                         className="row align-items-center position-relative mb-5"
//                         key={prod.productId}
//                       >
//                         <Link to={`/user/furniture/${prod.productId}`}>
//                           <div className="col-4 col-md-3" title="image">
//                             <img
//                               className="img-fluid"
//                               src={prod.images[0].url}
//                               alt="..."
//                             />
//                           </div>
//                           <div className="col position-static">
//                             <p className="mb-0 fw-bold">
//                               <a className="stretched-link text-body">
//                                 {prod.productName}
//                               </a>
//                               <br />
//                               <span className="text-muted">${prod.price}</span>
//                             </p>
//                           </div>
//                         </Link>
//                       </div>
//                     ))}
//         <a className="btn btn-link px-0 text-reset" href="./shop">
//           Tất cả <i className="fe fe-arrow-right ms-2"></i>
//         </a>
//       </div>
//     </>
//   );
// };
// export default SearchProd;
