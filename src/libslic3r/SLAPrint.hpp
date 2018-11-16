#ifndef slic3r_SLAPrint_hpp_
#define slic3r_SLAPrint_hpp_

#include "PrintBase.hpp"
#include "PrintExport.hpp"
#include "Point.hpp"

namespace Slic3r {

enum SLAPrintStep : unsigned int {
	slapsRasterize,
	slapsValidate,
	slapsCount
};

enum SLAPrintObjectStep : unsigned int {
	slaposObjectSlice,
	slaposSupportIslands,
	slaposSupportPoints,
	slaposSupportTree,
	slaposBasePool,
	slaposSliceSupports,
	slaposCount
};

class SLAPrint;
class GLCanvas;

using _SLAPrintObjectBase =
    PrintObjectBaseWithState<SLAPrint, SLAPrintObjectStep, slaposCount>;

class SLAPrintObject : public _SLAPrintObjectBase
{
private: // Prevents erroneous use by other classes.
    using Inherited = _SLAPrintObjectBase;

public:
    const Transform3d&      trafo()        const    { return m_trafo; }

    struct Instance {
    	Instance(ModelID instance_id, const Point &shift, float rotation) : instance_id(instance_id), shift(shift), rotation(rotation) {}
    	// ID of the corresponding ModelInstance.
		ModelID instance_id;
		// Slic3r::Point objects in scaled G-code coordinates
    	Point 	shift;
    	// Rotation along the Z axis, in radians.
    	float 	rotation; 
	};
    const std::vector<Instance>& instances() const { return m_instances; }

    // Get a support mesh centered around origin in XY, and with zero rotation around Z applied.
    // Support mesh is only valid if this->is_step_done(slaposSupportTree) is true.
    TriangleMesh            support_mesh() const;
    // Get a pad mesh centered around origin in XY, and with zero rotation around Z applied.
    // Support mesh is only valid if this->is_step_done(slaposPad) is true.
    TriangleMesh            pad_mesh() const;

    // I refuse to grantee copying (Tamas)
    SLAPrintObject(const SLAPrintObject&) = delete;
    SLAPrintObject& operator=(const SLAPrintObject&) = delete;

protected:
    // to be called from SLAPrint only.
    friend class SLAPrint;

	SLAPrintObject(SLAPrint* print, ModelObject* model_object);
    ~SLAPrintObject();

    void                    config_apply(const ConfigBase &other, bool ignore_nonexistent = false) { this->m_config.apply(other, ignore_nonexistent); }
    void                    config_apply_only(const ConfigBase &other, const t_config_option_keys &keys, bool ignore_nonexistent = false) 
    	{ this->m_config.apply_only(other, keys, ignore_nonexistent); }
    void                    set_trafo(const Transform3d& trafo) { m_trafo = trafo; }

    bool                    set_instances(const std::vector<Instance> &instances);
    // Invalidates the step, and its depending steps in SLAPrintObject and SLAPrint.
    bool                    invalidate_step(SLAPrintObjectStep step);

private:
    // Object specific configuration, pulled from the configuration layer.
    SLAPrintObjectConfig                    m_config;
    // Translation in Z + Rotation by Y and Z + Scaling / Mirroring.
    Transform3d                             m_trafo = Transform3d::Identity();
    std::vector<Instance> 					m_instances;

    // Which steps have to be performed. Implicitly: all
    std::vector<bool>                       m_stepmask;
    std::vector<ExPolygons>                 m_model_slices;

    class SupportData;
    std::unique_ptr<SupportData> m_supportdata;
};

using PrintObjects = std::vector<SLAPrintObject*>;

class TriangleMesh;

/**
 * @brief This class is the high level FSM for the SLA printing process.
 *
 * It should support the background processing framework and contain the
 * metadata for the support geometries and their slicing. It should also
 * dispatch the SLA printing configuration values to the appropriate calculation
 * steps.
 *
 * TODO (decide): The last important feature is the support for visualization
 * which (at least for now) will be implemented as a method(s) returning the
 * triangle meshes or receiving the rendering canvas and drawing on that
 * directly.
 *
 */
class SLAPrint : public PrintBaseWithState<SLAPrintStep, slapsCount>
{
private: // Prevents erroneous use by other classes.
    typedef PrintBaseWithState<SLAPrintStep, slapsCount> Inherited;

public:
    SLAPrint(): m_stepmask(slapsCount, true) {}

	virtual ~SLAPrint() { this->clear(); }

	PrinterTechnology	technology() const noexcept { return ptSLA; }

    void                clear() override;
    bool                empty() const override { return false; }
    ApplyStatus         apply(const Model &model, const DynamicPrintConfig &config) override;
    void                process() override;

    template<class Fmt> void export_raster(const std::string& fname) {
        if(m_printer) m_printer->save<Fmt>(fname);
    }
    const PrintObjects& objects() const { return m_objects; }

private:
    using SLAPrinter = FilePrinter<FilePrinterFormat::SLA_PNGZIP>;
    using SLAPrinterPtr = std::unique_ptr<SLAPrinter>;

    SLAPrinterConfig                m_printer_config;
    SLAMaterialConfig               m_material_config;
    PrintObjects                    m_objects;
    std::vector<bool>               m_stepmask;
    SLAPrinterPtr                   m_printer;

	friend SLAPrintObject;
};

} // namespace Slic3r

#endif /* slic3r_SLAPrint_hpp_ */
