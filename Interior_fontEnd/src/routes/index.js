import Home from "../Home";
import AdminPage from "../Admin/AdminPage";
import Login from "../Account/Login/Login";
import PageNotFound from "./NotFound/PageNotFound";
import AdminHome from "../Admin/Home/AdminHome";
import UserOverView from "../Admin/User/UserOverView";
import UserSearch from "../Admin/User/UserSearch";
import UserDetail from "../Admin/User/UserDetail";
import ProductOverView from "../Admin/Product/ProductOverView";
import UserPage from "../User/UserPage";
import About from "../User/About/About";
import Blog from "../User/Blog/Blog";
import HomePage from "../User/Home/HomePage";
import Shop from "../User/Shop/Shop";
import DetailProduct from "../User/Shop/DetailProduct";
import UserForm from "../User/Personal/UserForm";
import ChangePassword from "../User/Personal/ChangePass";
import OrderPage from "../User/Shop/OrderPage";
import Invoice from "../User/Shop/InvoiceComponent/Invoice";
import Payment from "../User/Checkout/Payment/Payment";
import Success from "../User/Checkout/Success";
import Failure from "../User/Checkout/Failure";
import Register from "../Account/Register/Register";
import ForgotPassword from "../Account/Login/ForgotPassword";
import VerifyCode from "../Account/Login/VerifyCode";
import ResetPassword from "../Account/Login/ResetPassword";
import Revenue from "../Admin/Revenue/RevenueOverview";

// Public Route
const publicRoutes = [
  { path: "/", component: Home },
  { path: "/login", component: Login },
  { path: "/user", component: UserPage },
  { path: "/register", component: Register },
  { path: "/forgotPassword", component: ForgotPassword },
  { path: "/verifyCode/:email", component: VerifyCode },
  { path: "/resetPassword", component: ResetPassword },
];

// Private Route
const privateRoutes = [
  {
    path: "/admin",
    component: AdminPage,
    childrenRoute: [
      {
        path: "",
        component: AdminHome,
      },
      {
        path: "user",
        childrenRoute: [
          {
            path: "overview",
            component: UserOverView,
          },
          {
            path: "search",
            component: UserSearch,
          },
          {
            path: "detail/:idUser",
            component: UserDetail,
          },
        ],
      },
      {
        path: "product",
        childrenRoute: [
          {
            path: "overview",
            component: ProductOverView,
          },
          {
            path: "search",
            component: UserSearch,
          },
          {
            path: "detail/:idUser",
            component: UserDetail,
          },
        ],
      },
      {
        path: "revenue",
        childrenRoute: [
          { path: "overview", 
            component: Revenue 
          }
        ],
      },
    ],
  },
  {
    path: "/user",
    component: UserPage,
    childrenRoute: [
      {
        path: "",
        component: HomePage,
      },
      {
        path: "about",
        component: About,
      },
      {
        path: "blog",
        component: Blog,
      },
      {
        path: "shop",
        childrenRoute: [
          {
            path: "",
            component: Shop,
          },
          {
            path: "furniture/:productId",
            component: DetailProduct,
          },
        ],
      },
      {
        path: "checkout",
        component: Payment,
      },
      {
        path: "success",
        component: Success,
      },
      {
        path: "failure",
        component: Failure,
      },
      {
        path: "detail",
        childrenRoute: [
          {
            path: "",
            component: UserForm,
          },
          {
            path: "change-password",
            component: ChangePassword,
          },
          {
            path: "orderPage",
            component: OrderPage,
          },
          {
            path: "orderPage/:orderId",
            component: Invoice,
          },
        ],
      },
    ],
  },
];

// Page not Found
const notFoundRoutes = [
  {
    path: "*",
    component: PageNotFound,
  },
];

export { publicRoutes, privateRoutes };
