
# Kịch bản thuyết trình — Slide 14 đến 19

Đồ án NET-CORE · Nhóm 9 · Môn IE106 Thiết kế giao diện người dùng

**Tổng thời lượng: 7–8 phút** (trung bình 1 phút 15 giây / slide)

| Slide | Chủ đề | Lấy từ báo cáo | Thời lượng |
|---|---|---|---|
| 14 | Vòng đời xử lý sự cố 4 bước | Chương 4.1 + 4.2 | 1'30 |
| 15 | Tập trung vào động từ cốt lõi | Chương 4.3 | 1'00 |
| 16 | Nhiệm vụ cốt lõi của người dùng | Chương 4.4 | 1'15 |
| 17 | Ba loại trạng thái cốt lõi | Chương 5.1 + 5.3 | 1'15 |
| 18 | Hai chế độ an toàn, bốn cấp phòng ngừa | Chương 5.2 + 5.4 | 1'30 |
| 19 | Kế hoạch Usability Testing | Chương 5.5 | 1'00 |

> **Ghi chú:** slide 14–16 thuộc **Chương 4** của báo cáo (Người dùng sẽ phải làm
> gì), slide 17–19 thuộc **Chương 5** (Người dùng có biết mình đang làm gì
> không). Chương 6 — Phân cấp nội dung — nằm ở **slide 23**, không nằm trong
> khoảng này.

---

## SLIDE 14 — Vòng đời xử lý sự cố (4 bước)

*(1 phút 30 giây)*

> Đến phần Thiết kế tương tác. Câu hỏi mà chương này trả lời là: **người dùng sẽ
> phải làm gì** khi mở hệ thống lên.
>
> Nhiệm vụ quan trọng nhất mà giao diện dẫn dắt là một hành trình khép kín — từ
> lúc phát hiện tín hiệu bất thường cho tới khi xác nhận sự cố đã được giải
> quyết. Chúng em chuẩn hoá hành trình đó thành **bốn trạng thái tuần tự**.
>
> *(chỉ vào từng bước)*
>
> Bước một, **NEW — Mới phát**. Hệ thống vừa ghi nhận, chưa ai nhận trách nhiệm.
> Ở trạng thái này giao diện chỉ gợi ý đúng một hành động: *Nhận xử lý*.
>
> Bước hai, **ACKNOWLEDGED — Đã tiếp nhận**. Đã có người đứng tên. Lời gọi hành
> động đổi thành *Bắt đầu điều tra*.
>
> Bước ba, **INVESTIGATING — Đang điều tra**. Người phụ trách kiểm tra nguyên
> nhân, và giao diện gợi ý *Chuyển sang Resolve*.
>
> Bước bốn, **RESOLVED — Đã giải quyết**. Nhưng ở đây có một ràng buộc quan
> trọng: muốn đóng sự cố thì **bắt buộc phải có bằng chứng** — nguyên nhân gốc
> rễ, hành động khắc phục, và kết quả xác minh.
>
> Ba nguyên tắc chi phối luồng này 
> Technical supervisor admin
---

## SLIDE 15 — Tập trung vào động từ cốt lõi

*(1 phút)*

> Ở **dòng sự cố trên Dashboard**, hai động từ là *Xem Topology* và *Xử lý* —
> đặt ngay trên từng dòng, người dùng không phải đi tìm.
>
> Ở **Chi tiết thiết bị**, động từ là *Tắt nguồn* — và đi kèm ngoặc đơn: **yêu
> cầu xác nhận**. Đây là hành động rủi ro cao nên không bao giờ thực thi ngay.
>
> Ở **Sơ đồ Topology**, động từ là *Lưu Toạ Độ*. Chữ "Lưu" ở đây có chủ ý: người
> dùng kéo thả xong vẫn phải bấm lưu, nên có cơ hội đổi ý.
>
> Điểm chung của cả ba: người dùng đọc nhãn là biết **ngay** điều gì sắp xảy ra.
> Đó là khác biệt giữa một nút hành động tốt và một nút gây do dự.

---

## SLIDE 16 — Nhiệm vụ cốt lõi của người dùng

*(1 phút 15 giây)*

> Để xác định người dùng thật sự cần gì, nhóm em dùng phương pháp
> **Jobs-to-be-Done** — tức là hỏi "người dùng cần *làm được* việc gì", độc lập
> với chi tiết giao diện cụ thể. Bốn nhiệm vụ cốt lõi rút ra được:
>
> **Phân loại ưu tiên** — khi có cảnh báo mới, người trực cần biết ngay mức độ,
> thiết bị nào và phạm vi ảnh hưởng, để quyết định xử lý cái nào trước.
>
> **Duy trì ngữ cảnh** — khi nhận một sự cố, họ cần giữ nguyên mạch thông tin
> giữa cảnh báo, thiết bị và sơ đồ mạng, để không phải đi tìm lại từ đầu.
>
> **Điều tra dữ liệu** — cần đối chiếu **đồng thời** nhật ký lỗi và thông số đo
> kiểm trong cùng một khoảng thời gian, tránh kiểm tra lặp hoặc bỏ sót.
>
> **Lưu vết bằng chứng** — trước khi đóng sự cố phải ghi nguyên nhân và hành
> động, để người khác kiểm tra lại được.

---

## SLIDE 17 — Ba loại trạng thái cốt lõi

*(1 phút 15 giây)*

> Sang phần **Hiển thị trạng thái**. Phần này trả lời câu hỏi: *người dùng có
> biết mình đang làm gì hay không*.
>
> Đây chính là nguyên tắc khả dụng **đầu tiên và quan trọng nhất** của Jakob
> Nielsen — *Visibility of System Status*: hệ thống phải luôn cho người dùng
> biết điều gì đang xảy ra, bằng phản hồi phù hợp, trong thời gian hợp lý.
>
> Nhưng trong bối cảnh trung tâm giám sát mạng, câu hỏi này còn nặng hơn một
> tầng. Người vận hành không chỉ cần biết *"giao diện đang làm gì"*, mà còn cần
> biết **"dữ liệu mình đang nhìn có còn đúng với thực tế hạ tầng hay không"**.
>
> Vì vậy hệ thống phải hiển thị minh bạch **ba loại trạng thái**:
>
> **Trạng thái thao tác** — đang tải, thành công, hay lỗi. Đây là phản hồi cho
> hành động người dùng vừa làm.
>
> **Trạng thái nghiệp vụ** — vòng đời sự cố và mức độ nghiêm trọng, tức trạng
> thái của chính đối tượng đang xem.
>
> **Trạng thái dữ liệu** — độ tươi mới và tình trạng kết nối tới backend.
>
> *(chỉ sang phần dưới)*
>
> Về độ tươi dữ liệu, hệ thống **đã làm được**: có chỉ báo quét dữ liệu định kỳ,
> và hiệu ứng **nhịp đập** trên những nút mạng đang gặp sự cố — giúp người dùng
> cảm nhận hệ thống đang sống, không phải ảnh chụp tĩnh.
>
> Nhưng vẫn còn **khoảng trống**: khi mất kết nối tới backend, giao diện chưa
> cảnh báo. Người dùng có thể nhìn dữ liệu cũ mà tưởng là hiện trạng. Nhóm em đề
> xuất bổ sung một **dải băng cảnh báo màu vàng** ở đầu trang, ghi rõ kiểu *"Mất
> kết nối Telemetry — đang hiển thị dữ liệu lưu đệm lúc 14:32"*.

---

## SLIDE 18 — Hai chế độ an toàn, bốn cấp độ phòng ngừa

Slide này tập trung vào một nguyên tắc chung: phòng ngừa sai sót bằng cách kiểm soát mức độ can thiệp của người dùng.

Đầu tiên, với sơ đồ Topology, chúng tôi áp dụng thiết kế An toàn Hai Chế độ.

Observe Mode là chế độ mặc định. Người dùng có thể xem thông tin, zoom hoặc di chuyển sơ đồ, nhưng không thể vô tình làm thay đổi cấu hình.

Khi cần chỉnh sửa, người dùng phải chủ động chuyển sang Manage Mode. Khi đó các công cụ chỉnh sửa mới xuất hiện, đồng thời thao tác lưu được thực hiện rõ ràng và có cơ chế khôi phục nếu lưu thất bại.

Điểm quan trọng ở đây là tạo ra một ranh giới rõ ràng giữa quan sát và chỉnh sửa, giúp giảm nguy cơ thao tác nhầm trong quá trình giám sát hoặc xử lý sự cố.

Từ nguyên tắc đó, chúng tôi mở rộng thành 4 cấp độ phản hồi theo mức độ rủi ro.

Cấp 1: thao tác thông thường như lọc hoặc chuyển trang → thực hiện ngay.
Cấp 2: thay đổi trạng thái → yêu cầu xác nhận nhanh.
Cấp 3: thay đổi cấu hình hoặc topology → phải chủ động bật Manage Mode.
Cấp 4: thao tác có rủi ro cao như tắt thiết bị hoặc xoá dữ liệu → hiển thị cảnh báo rõ hậu quả trước khi tiếp tục.

Như vậy, mức độ kiểm soát tăng theo mức độ rủi ro. Thao tác nhỏ không bị làm phiền bởi quá nhiều xác nhận, trong khi những thao tác quan trọng luôn có thêm một lớp bảo vệ trước khi thực hiện.

## SLIDE 19 — Kế hoạch Usability Testing

Ba slide vừa rồi là lập luận từ góc nhìn thiết kế. Để kiểm chứng, nhóm em xây dựng bộ Usability Testing với 5 nhiệm vụ, tập trung vào ba tiêu chí.

Thứ nhất, nhận thức màu sắc: người dùng phải hiểu đúng mức độ nghiêm trọng mà không cần giải thích, mục tiêu trên 90%.

Thứ hai, quyền hạn của AI: người dùng phải hiểu AI chỉ hỗ trợ, không tự ý thay đổi IP, tắt thiết bị hay đóng sự cố. Mục tiêu là 5 trên 5 người hiểu đúng.

Cuối cùng là khả năng khôi phục khi nhập lỗi: ở T5, nhóm cố tình tạo lỗi để kiểm tra người dùng có nhận ra và dữ liệu đã nhập có được giữ lại hay không.

---

# PHỤ LỤC — Gợi ý trình bày

## Câu chuyển giữa các slide

| Từ → đến | Câu nối |
|---|---|
| 13 → 14 | "Sau khi biết người dùng **đang ở đâu**, câu hỏi tiếp theo là họ **sẽ phải làm gì**." |
| 14 → 15 | "Có vòng đời rồi, nhưng làm sao người dùng biết bấm vào đâu ở mỗi bước?" |
| 15 → 16 | "Vậy rốt cuộc người dùng cần *làm được* những việc gì?" |
| 16 → 17 | "Biết phải làm gì là một chuyện. Biết mình **đang** làm gì lại là chuyện khác." |
| 17 → 18 | "Biết trạng thái rồi, còn làm sao để không lỡ tay làm sai?" |
| 18 → 19 | "Tất cả những điều trên đều là lập luận của người thiết kế. Kiểm chứng thế nào?" |
| 19 → 20 | "Và khi lỗi vẫn xảy ra, hệ thống xử lý ra sao?" |

## Ba con số nên nhấn giọng

- **4 bước** trong vòng đời sự cố
- **4 cấp độ** phòng ngừa sai sót
- **90%** và **5/5** — hai mục tiêu kiểm thử

## Ba điểm mạnh nên nhấn

1. **Không cho nhảy cóc trạng thái** + tự động ghi nhật ký kiểm toán
2. **Mẫu An toàn Hai Chế độ** — báo cáo đánh giá là "một trong những quyết định
   thiết kế xuất sắc nhất của dự án"
3. **Phân tầng xác nhận theo mức nguy hiểm** — tránh cả mỏi tay lẫn hời hợt

## Hai điểm trung thực nên chủ động nêu

Nêu trước sẽ tốt hơn để hội đồng hỏi:

1. **Slide 16** — lưu vết bằng chứng mới dừng ở hộp thoại xác nhận, chưa có biểu
   mẫu bắt buộc. Đây là lỗi P0.
2. **Slide 19** — kế hoạch kiểm thử chưa chạy với người dùng thật, nên vẫn là
   giả thuyết.

## Câu hỏi hội đồng có thể hỏi

**"Vì sao không cho chuyển thẳng NEW sang RESOLVED?"**
→ Vì mất dấu vết trách nhiệm. Không biết ai xử lý, xử lý thế nào. Trong vận hành
mạng, sự cố lặp lại là chuyện thường — không có lịch sử điều tra thì lần sau phải
làm lại từ đầu.

**"Manage Mode có gây phiền không?"**
→ Có thêm một thao tác, nhưng chỉ với người muốn chỉnh sửa. Người xem — chiếm đa
số thời gian sử dụng — không bị ảnh hưởng. Đổi lại là loại bỏ được nguy cơ kéo
lệch node do vô ý.

**"Chưa test với người dùng thật thì sao dám kết luận?"**
→ Nhóm em **không** kết luận. Báo cáo ghi rõ đây là giả thuyết thiết kế. Các mục
tiêu 90% và 5/5 là ngưỡng đặt ra để kiểm chứng, không phải kết quả đã đạt.
