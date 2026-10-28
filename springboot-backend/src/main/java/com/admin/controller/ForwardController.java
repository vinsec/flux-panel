package com.admin.controller;

import com.admin.common.aop.LogAnnotation;
import com.admin.common.annotation.RequireRole;
import com.admin.common.dto.ForwardDto;
import com.admin.common.dto.ForwardUpdateDto;
import com.admin.common.lang.R;
import com.admin.service.ForwardService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * <p>
 *  前端控制器
 * </p>
 *
 * @author QAQ
 * @since 2025-06-03
 */
@RestController
@CrossOrigin
@RequestMapping("/api/v1/forward")
public class ForwardController extends BaseController {

    @Autowired
    private ForwardService forwardService;

    @LogAnnotation
    @PostMapping("/create")
    public R create(@Validated @RequestBody ForwardDto forwardDto) {
        return forwardService.createForward(forwardDto);
    }

    @LogAnnotation
    @PostMapping("/list")
    public R readAll() {
        return forwardService.getAllForwards();
    }

    @LogAnnotation
    @PostMapping("/update")
    public R update(@Validated @RequestBody ForwardUpdateDto forwardUpdateDto) {
        return forwardService.updateForward(forwardUpdateDto);
    }

    @LogAnnotation
    @PostMapping("/delete")
    public R delete(@RequestBody Map<String, Object> params) {
        Long id = Long.valueOf(params.get("id").toString());
        return forwardService.deleteForward(id);
    }

    @LogAnnotation
    @PostMapping("/force-delete")
    public R forceDelete(@RequestBody Map<String, Object> params) {
        Long id = Long.valueOf(params.get("id").toString());
        return forwardService.forceDeleteForward(id);
    }

    @LogAnnotation
    @PostMapping("/pause")
    public R pause(@RequestBody Map<String, Object> params) {
        Long id = Long.valueOf(params.get("id").toString());
        return forwardService.pauseForward(id);
    }

    @LogAnnotation
    @PostMapping("/resume")
    public R resume(@RequestBody Map<String, Object> params) {
        Long id = Long.valueOf(params.get("id").toString());
        return forwardService.resumeForward(id);
    }

    /**
     * 转发诊断功能
     * @param params 包含forwardId的参数
     * @return 诊断结果
     */
    @LogAnnotation
    @PostMapping("/diagnose")
    public R diagnoseForward(@RequestBody Map<String, Object> params) {
        Long forwardId = Long.valueOf(params.get("forwardId").toString());
        if(params.containsKey("probe") && !(params.get("probe") instanceof Boolean))return R.err("probe must be boolean");
        for(String key:new String[]{"clientIP","ingressInterface"})if(params.containsKey(key)&&params.get(key)!=null&&!(params.get(key) instanceof String))return R.err(key+" must be text");
        return forwardService.diagnoseForward(forwardId,(String)params.get("clientIP"),(String)params.get("ingressInterface"),Boolean.TRUE.equals(params.get("probe")));
    }

    /**
     * 更新转发排序
     * @param params 包含forwards数组的参数，每个元素包含id和inx
     * @return 更新结果
     */
    @LogAnnotation
    @PostMapping("/update-order")
    public R updateForwardOrder(@RequestBody Map<String, Object> params) {
        return forwardService.updateForwardOrder(params);
    }

}
